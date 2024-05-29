package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	var devs, srvAddr string
	flag.StringVar(&devs, "dev", "",
		"Comma seperated list of devices to attach to")
	flag.StringVar(&srvAddr, "srvAddr", ":9042", "server host:port")
	flag.Parse()

	app, err := newApp(srvAddr, devs)
	if err != nil {
		return err
	}
	defer app.close()

	if err := app.init(); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("closing app from signal")
		cancel()
	}()

	return app.run(ctx)
}
