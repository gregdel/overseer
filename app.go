package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
)

// ip        - 4
// ifindex   - 4
// mac       - 6
// padding   - 2
// msg       - 128
// padding   - 4
const perfRecordSize = 148

type ebpfObjects struct {
	XDP    *ebpf.Program `ebpf:"overseer"`
	Stats  *ebpf.Map     `ebpf:"stats"`
	Events *ebpf.Map     `ebpf:"events"`
}

type app struct {
	devs          []string
	server        http.Server
	ebpf          ebpfObjects
	registry      *prometheus.Registry
	cache         *cache
	statsInterval time.Duration
}

func newApp(srvAddr, devs string, statsInterval time.Duration) (*app, error) {
	mux := http.NewServeMux()
	app := &app{
		devs:          strings.Split(devs, ","),
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
	prog := bytes.NewReader(xdpProg)
	spec, err := ebpf.LoadCollectionSpecFromReader(prog)
	if err != nil {
		return err
	}

	if err := spec.LoadAndAssign(&app.ebpf, nil); err != nil {
		return err
	}

	for _, dev := range app.devs {
		if err := app.handleXDPOnDev(dev, app.ebpf.XDP.FD()); err != nil {
			fmt.Printf("Failed to attach XDP program on %s: %s\n", dev, err)
		}
	}

	return nil
}

func (app *app) close() {
	if app.ebpf.XDP != nil {
		app.ebpf.XDP.Close()
	}

	if app.ebpf.Stats != nil {
		app.ebpf.Stats.Close()
	}

	for _, dev := range app.devs {
		if err := app.handleXDPOnDev(dev, -1); err != nil {
			fmt.Printf("Failed to attach XDP program on %s: %s\n", dev, err)
		}
	}
}

func (app *app) handleXDPOnDev(name string, fd int) error {
	if name == "" {
		return fmt.Errorf("missing device name")
	}

	dev, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}

	if err := netlink.LinkSetXdpFd(dev, fd); err != nil {
		return err
	}

	action := "loaded on"
	if fd == -1 {
		action = "unloaded from"
	}
	fmt.Printf("XDP program %s device %q\n", action, name)

	return nil
}

func (app *app) readEvents(ctx context.Context) {
	reader, err := perf.NewReader(app.ebpf.Events, os.Getpagesize())
	if err != nil {
		fmt.Println("failed to get perf reader", err)
		return
	}
	defer reader.Close()

	fmt.Println("Starting to read perf events...")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		reader.SetDeadline(time.Now().Add(time.Second))

		record, err := reader.Read()
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				fmt.Println("failed to read perf event", err)
			}
			continue
		}

		if len(record.RawSample) != perfRecordSize {
			fmt.Printf("invalid sample size got %d expected %d\n",
				len(record.RawSample), perfRecordSize)
			continue
		}

		k := &key{}
		if err := k.UnmarshalBinary(record.RawSample[:k.size()]); err != nil {
			fmt.Println("failed to unmarshal event", err)
			continue
		}

		v := string(record.RawSample[k.size():])

		// TODO: log this properly
		fmt.Println(k, v)

		if record.LostSamples != 0 {
			fmt.Printf("lost %d record samples\n", record.LostSamples)
			return
		}
	}
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
		fmt.Printf("%s %s@%s pkts:%d bytes:%d last_seen:%s ago\n",
			k.ip, k.macaddr, app.cache.linkName(k.ifindex),
			v.packets, v.bytes, time.Since(v.lastSeen),
		)
	}

	if err := iterator.Err(); err != nil {
		fmt.Println("got error:", err)
	}
}
