package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"gopkg.in/fsnotify.v1"
)

func (app *app) handleDnsmasq(ctx context.Context) error {
	if app.dnsmasqLeases == "" {
		fmt.Println("No dnsmasq lease file, ignoring")
		return nil
	}

	if err := app.readDnsmasqLeases(); err != nil {
		return err
	}

	// TODO: handle file creation / deletion

	// Watch file and handle events
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				if event.Op != fsnotify.Write {
					continue
				}

				fmt.Println("Dnsmasq file changed, updating")
				if err := app.readDnsmasqLeases(); err != nil {
					fmt.Println("Failed to read dnsmasq leases:", err)
					continue
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)
			}
		}
	}()

	err = watcher.Add(app.dnsmasqLeases)
	if err != nil {
		fmt.Println("Failed to watch dnsmasq leases file", err)
	}

	<-ctx.Done()
	return nil
}

func (app *app) readDnsmasqLeases() error {
	file, err := os.Open(app.dnsmasqLeases)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			fmt.Println("failed to parse dnsmasq line with fileds", fields)
			continue
		}

		mac, err := net.ParseMAC(fields[1])
		if err != nil {
			fmt.Println("failed to parse lease macaddr", err)
			continue
		}

		if net.ParseIP(fields[2]) == nil {
			fmt.Println("failed to parse lease ip", err)
			continue
		}

		name := fields[3]
		app.cache.setLeaseName(mac.String(), name)
	}

	return scanner.Err()
}
