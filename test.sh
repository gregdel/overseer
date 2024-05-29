#!/bin/sh

project_name=overseer
ns_name="$project_name"
dev_name="$project_name"
ip_prefix=100.64.42

if [ "$(id -u)" != "0" ]; then
	echo "This script must be run as root"
	exit 1
fi

_log() {
	echo "$@"
}

if [ -e "/run/netns/$ns_name" ]; then
	_log "Namespace $ns_name found, deleting..."
	ip netns del "$ns_name"
	sleep 1
fi

[ -d "/sys/kernel/debug" ] || mount -t debugfs none /sys/kernel/debug

_log "Creating network namespace $ns_name"
ip netns add "$ns_name"

_log "Creating veth pair $dev_name <-> host"
ip link add "$dev_name" type veth peer name host netns overseer
ip link set "$dev_name" up
ip -n "$ns_name" link set host up

_log "Adding IPs $dev_name:$ip_prefix.0 <-> host:$ip_prefix.1"
ip addr add "$ip_prefix.0/31" dev "$dev_name"
ip -n "$ns_name" addr add "$ip_prefix.1/31" dev host

_log "Attaching XDP program on $dev_name"
ip link set xdp object ./kern.o sec xdp.frags program "$project_name" dev "$dev_name"
ip -n "$ns_name" link set xdp object ./kern.o sec xdp.frags program dummy_pass dev host

_log "Pinging host to get one packet flowing"
ping -c 1 "$ip_prefix.1" >/dev/null

_log "Showing trace"
tail -n 10 /sys/kernel/debug/tracing/trace

_log "All done"
