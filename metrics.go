package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

var promKeyLabels = []string{"macaddr", "ip", "dev", "device_name", "direction"}

func (app *app) descPkts() *prometheus.Desc {
	return prometheus.NewDesc(
		"overseer_packets_total",
		"Number of packet seen by overseer in number of packets",
		promKeyLabels, prometheus.Labels{},
	)
}

func (app *app) descBytes() *prometheus.Desc {
	return prometheus.NewDesc(
		"overseer_bytes_total",
		"Number of packet seen by overseer in bytes",
		promKeyLabels, prometheus.Labels{},
	)
}

func (app *app) Describe(c chan<- *prometheus.Desc) {
	c <- app.descPkts()
	c <- app.descBytes()
}

func (app *app) Collect(c chan<- prometheus.Metric) {
	var k key
	var v value
	iterator := app.ebpf.Stats.Iterate()
	for iterator.Next(&k, &v) {
		deviceName, _ := app.cache.leaseName(k.macaddr.String())
		c <- prometheus.MustNewConstMetric(
			app.descPkts(),
			prometheus.CounterValue,
			float64(v.packets),
			k.macaddr.String(), k.ip.String(),
			app.cache.linkName(k.ifindex),
			deviceName, k.direction.String(),
		)
		c <- prometheus.MustNewConstMetric(
			app.descBytes(),
			prometheus.CounterValue,
			float64(v.bytes),
			k.macaddr.String(), k.ip.String(),
			app.cache.linkName(k.ifindex),
			deviceName, k.direction.String(),
		)
	}

	if err := iterator.Err(); err != nil {
		logErr("metrics", "Failed to iterate on stats map: %q\n", err)
	}
}
