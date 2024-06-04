package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
)

var ebpfPinPath = "/sys/fs/bpf"

// ip        - 4
// ifindex   - 4
// mac       - 6
// padding   - 2
// event     - 1
// padding   - 3
const perfRecordSize = 20

type ebpfObjects struct {
	Ingress *ebpf.Program `ebpf:"overseer_ingress"`
	Egress  *ebpf.Program `ebpf:"overseer_egress"`
	Stats   *ebpf.Map     `ebpf:"overseer_stats"`
	Events  *ebpf.Map     `ebpf:"overseer_events"`
}

type app struct {
	devs          []string
	server        http.Server
	dnsmasqLeases string
	ebpf          ebpfObjects
	registry      *prometheus.Registry
	cache         *cache
	statsInterval time.Duration
}

func newApp(srvAddr, devs, dnsmasqLeases string, statsInterval time.Duration) (*app, error) {
	mux := http.NewServeMux()
	app := &app{
		devs:          strings.Split(devs, ","),
		dnsmasqLeases: dnsmasqLeases,
		registry:      prometheus.NewRegistry(),
		statsInterval: statsInterval,
		cache:         newCache(),
		server: http.Server{
			Addr:    srvAddr,
			Handler: mux,
		},
	}

	if len(app.devs) == 0 {
		return nil, fmt.Errorf("missing --devs option")
	}

	app.registry.Register(app)
	mux.Handle("/metrics", promhttp.HandlerFor(app.registry, promhttp.HandlerOpts{
		Registry: app.registry,
	}))

	return app, nil
}

func (app *app) init() error {
	prog := bytes.NewReader(ebpfProg)
	spec, err := ebpf.LoadCollectionSpecFromReader(prog)
	if err != nil {
		return err
	}

	// TODO: get pin path from command line
	// TODO: add option to force the cleanup of pinned path
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: ebpfPinPath},
		Programs: ebpf.ProgramOptions{
			// LogLevel: ebpf.LogLevelStats,
			LogLevel: ebpf.LogLevelInstruction,
		},
	}

	if err := spec.LoadAndAssign(&app.ebpf, opts); err != nil {
		return err
	}

	for _, dev := range app.devs {
		if err := app.attachTCX(dev); err != nil {
			fmt.Printf("Failed to attach tcx program on %s: %s\n", dev, err)
		}
	}

	return nil
}

func (app *app) close() {
	for _, prog := range []*ebpf.Program{
		app.ebpf.Ingress,
		app.ebpf.Egress,
	} {
		if prog == nil {
			continue
		}
		prog.Close()
	}

	// Delete all pinned files
	files, err := os.ReadDir(ebpfPinPath)
	if err != nil {
		fmt.Println("Failed to read pinned path", err)
	}

	for _, file := range files {
		name := file.Name()
		if file.IsDir() || !strings.Contains(name, "overseer_") {
			continue
		}

		path := filepath.Join(ebpfPinPath, name)
		fmt.Println("Removing pinned object", path)
		if err := os.Remove(path); err != nil {
			fmt.Println("Failed to remove pinned path", err)
		}
	}
}

func (app *app) attachTCX(name string) error {
	if name == "" {
		return fmt.Errorf("missing device name")
	}

	dev, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}

	for _, direction := range []direction{directionIngress, directionEgress} {
		var prog *ebpf.Program
		var attach ebpf.AttachType
		var l link.Link
		if direction == directionIngress {
			prog = app.ebpf.Ingress
			attach = ebpf.AttachTCXIngress
		} else {
			prog = app.ebpf.Egress
			attach = ebpf.AttachTCXEgress
		}

		l, err := link.AttachTCX(link.TCXOptions{
			Program:   prog,
			Attach:    attach,
			Interface: dev.Attrs().Index,
			Anchor:    link.Tail(),
		})
		if err != nil {
			return fmt.Errorf("attaching tcx: %w", err)
		}

		pinPath := filepath.Join(ebpfPinPath, "overseer_tcx_"+name+"_"+direction.String())
		if err := l.Pin(pinPath); err != nil {
			fmt.Println("Failed to pin tcx program:", err)
			continue
		}

		fmt.Printf("TCX program loaded on dev:%q direction:%q\n", name, direction)
	}

	return nil
}

func (app *app) run(ctx context.Context) error {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("Starting HTTP server with addr", app.server.Addr)
		if err := app.server.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Println("HTTP server ListenAndServe:", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		app.readEvents(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		app.handleDnsmasq(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		if app.statsInterval == 0 {
			return
		}

		ticker := time.NewTicker(app.statsInterval)
		defer ticker.Stop()

		exit := false
		for !exit {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				app.printStats()
			}
		}
	}()

	<-ctx.Done()

	if err := app.server.Shutdown(context.Background()); err != nil {
		fmt.Println("HTTP server Shutdown:", err)
	}

	wg.Wait()
	return nil
}

func (app *app) printStats() {
	var k key
	var v value

	fmt.Println("Stats:")
	iterator := app.ebpf.Stats.Iterate()
	for iterator.Next(&k, &v) {
		fmt.Printf("%s %s@%s %d pkts:%d bytes:%d last_seen:%s ago\n",
			k.ip, k.macaddr, app.cache.linkName(k.ifindex), k.direction,
			v.packets, v.bytes, time.Since(v.lastSeen),
		)
	}

	if err := iterator.Err(); err != nil {
		fmt.Println("got error:", err)
	}
}
