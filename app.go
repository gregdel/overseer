package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
)

// ip        - 4
// mac       - 6
// padding   - 2
// msg       - 128
const perfRecordSize = 140

type ebpfObjects struct {
	XDP    *ebpf.Program `ebpf:"overseer"`
	Stats  *ebpf.Map     `ebpf:"stats"`
	Events *ebpf.Map     `ebpf:"events"`
}

type app struct {
	server http.Server
	ebpf   ebpfObjects
}

func newApp() *app {
	mux := http.NewServeMux()
	app := &app{
		server: http.Server{
			Handler: mux,
		},
	}

	prometheus.Register(app)
	mux.Handle("/metrics", promhttp.Handler())

	return app
}

func (app *app) init() error {
	prog := bytes.NewReader(xdpProg)
	spec, err := ebpf.LoadCollectionSpecFromReader(prog)
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(&app.ebpf, nil)
}

func (app *app) close() {
	if app.ebpf.XDP != nil {
		app.ebpf.XDP.Close()
	}

	if app.ebpf.Stats != nil {
		app.ebpf.Stats.Close()
	}
}

func (app *app) attachXDP(name string) error {
	dev, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}

	if err := netlink.LinkSetXdpFd(dev, app.ebpf.XDP.FD()); err != nil {
		return err
	}

	fmt.Println("xdp program loaded on device", name)

	return nil
}

func (app *app) readEvents(ctx context.Context) {
	reader, err := perf.NewReader(app.ebpf.Events, os.Getpagesize())
	if err != nil {
		fmt.Println("failed to get perf reader", err)
		return
	}
	defer reader.Close()

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
		if err := k.UnmarshalBinary(record.RawSample[:12]); err != nil {
			fmt.Println("failed to unmarshal event", err)
			continue
		}

		v := string(record.RawSample[12:])

		// TODO: log this properly
		fmt.Println(k, v)

		if record.LostSamples != 0 {
			fmt.Printf("lost %d record samples\n", record.LostSamples)
			return
		}
	}
}

func (app *app) run(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := app.server.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Println("HTTP server ListenAndServe:", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		app.readEvents(ctx)
	}()

	fmt.Println("running app")
	exit := false
	for !exit {
		select {
		case <-ctx.Done():
			exit = true
		case <-ticker.C:
			app.printStats()
		}
	}

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
		fmt.Println("\t", k, v)
	}

	if err := iterator.Err(); err != nil {
		fmt.Println("got error:", err)
	}
}
