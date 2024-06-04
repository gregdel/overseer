package main

import (
	"bufio"
	"context"
	"log"
	"net"
	"os"
	"strings"

	"gopkg.in/fsnotify.v1"
)

func (app *app) handleDnsmasq(ctx context.Context) error {
	if app.dnsmasqLeases == "" {
		logInfo("dnsmasq", "No lease file, ignoring\n")
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

				logInfo("dnsmasq", "Lease file updated\n")
				if err := app.readDnsmasqLeases(); err != nil {
					logErr("dnsmasq", "Failed to read leases file: %s\n", err)
					continue
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logErr("dnsmasq", "Got watcher error: %s\n", err)
			}
		}
	}()

	err = watcher.Add(app.dnsmasqLeases)
	if err != nil {
		logErr("dnsmasq", "Failed to watch dnsmasq leases file: %s\n", err)
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
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			logErr("dnsmasq", "Failed to parse line: %s\n", line)
			continue
		}

		mac, err := net.ParseMAC(fields[1])
		if err != nil {
			logErr("dnsmasq", "Failed to parse macaddr: %s\n", err)
			continue
		}

		if net.ParseIP(fields[2]) == nil {
			logErr("dnsmasq", "Failed to parse IP: %s\n", err)
			continue
		}

		name := fields[3]
		app.cache.setLeaseName(mac.String(), name)
	}

	return scanner.Err()
}
