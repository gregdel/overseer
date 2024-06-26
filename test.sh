#!/bin/sh

project_name=overseer
ns_name="$project_name"
dev_name="$project_name"
ip_prefix=100.64.42
ns_macaddr="de:ad:be:ef:ba:be"

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

_log "Creating network namespace $ns_name"
ip netns add "$ns_name"

_log "Creating veth pair $dev_name <-> host"
ip link add "$dev_name" type veth peer name host netns overseer
ip link set "$dev_name" up
ip -n "$ns_name" link set host addr "$ns_macaddr" up

_log "Adding IPs $dev_name:$ip_prefix.0 <-> host:$ip_prefix.1"
ip addr add "$ip_prefix.0/31" dev "$dev_name"
ip -n "$ns_name" addr add "$ip_prefix.1/31" dev host

_log "Pinging host to get one packet flowing"
ping -c 1 "$ip_prefix.1" >/dev/null
_log "Pinging host to get one packet flowing"
_log "Everything is ready"

read -r macaddr _ < /sys/class/net/overseer/address
cat ->/run/dnsmasq.leases <<EOF
1717232696 $macaddr $ip_prefix.0    client1 $macaddr
1717232697 $ns_macaddr $ip_prefix.1 client2 $macaddr
EOF

_generate_traffic() {
	sleep 2
	ping -c 1 "$ip_prefix.1" >/dev/null
}
_generate_traffic &

./"$project_name" --dev "$project_name"
