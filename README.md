# Overseer

Monitor private traffic with eBPF and TCX, expose metrics to prometheus.

## General idea

Bind this program to a linux bridge to monitor the private traffic on the LAN.  It counts packets and bytes for a each unique (ip, device, macaddress, direction) group.  Only private IPs will be accounted for.

It can "resolve" names using a dnsmasq lease file.

Only work with IPv4 for now.

The result of the build is a statically compiled binary embedding the eBPF code.

## Output

```
# curl -Ss http://localhost:9042/metrics
# HELP overseer_bytes_total Number of packet seen by overseer in bytes
# TYPE overseer_bytes_total counter
overseer_bytes_total{dev="overseer",device_name="client2",direction="egress",ip="100.64.42.1",macaddr="de:ad:be:ef:ba:be"} 98
overseer_bytes_total{dev="overseer",device_name="client2",direction="ingress",ip="100.64.42.1",macaddr="de:ad:be:ef:ba:be"} 98
# HELP overseer_packets_total Number of packet seen by overseer in number of packets
# TYPE overseer_packets_total counter
overseer_packets_total{dev="overseer",device_name="client2",direction="egress",ip="100.64.42.1",macaddr="de:ad:be:ef:ba:be"} 1
overseer_packets_total{dev="overseer",device_name="client2",direction="ingress",ip="100.64.42.1",macaddr="de:ad:be:ef:ba:be"} 1
# HELP promhttp_metric_handler_errors_total Total number of internal errors encountered by the promhttp metric handler.
# TYPE promhttp_metric_handler_errors_total counter
promhttp_metric_handler_errors_total{cause="encoding"} 0
promhttp_metric_handler_errors_total{cause="gathering"} 0
```
