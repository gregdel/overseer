#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES 256
#define DIR_INGRESS 0
#define DIR_EGRESS  1

enum perf_event_type { EVENT_NEW, EVENT_FAILED };

struct key {
	__be32 ip;
	__u32 ifindex;
	unsigned char macaddr[ETH_ALEN];
	__u8 direction;
	__u8 padding;
};

struct value {
	__u64 pkts;
	__u64 bytes;
	__u64 last_seen;
};

struct event {
	struct key key;
	enum perf_event_type type;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} overseer_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct key));
	__uint(value_size, sizeof(struct value));
	__uint(max_entries, MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} overseer_stats SEC(".maps");

__always_inline
void send_event(struct __sk_buff *skb, struct key key, enum perf_event_type type) {
	struct event e = { .key = key, .type = type };
	bpf_perf_event_output(skb, &overseer_events, BPF_F_CURRENT_CPU,
			      &e, sizeof(struct event));
}

__always_inline
int is_private(__be32 ip) {
	__u32 nip = bpf_ntohl(ip);
	__u32 p1 = nip >> 24;
	__u32 p2 = (nip & 0x00FF0000) >> 16;

	if ((p1 == 10) ||
	    ((p1 == 192) && (p2 == 168)) ||
	    ((p1 == 100) && (p2 == 64))) {
		return 1;
	}

	return 0;
}

__always_inline
void update_stats(struct __sk_buff *skb, __u8 direction,
		  __be32 ip, unsigned char macaddr[ETH_ALEN]) {

	if (!is_private(ip))
		return;

	struct key key = {
		.direction = direction,
		.ip = ip,
		.ifindex = direction == DIR_EGRESS ?
			skb->ifindex : skb->ingress_ifindex,
	};
	__builtin_memcpy(&key.macaddr, macaddr, ETH_ALEN);

	struct value v = {
		.pkts = 1,
		.bytes = skb->len,
		v.last_seen = bpf_ktime_get_tai_ns(),
	};

	struct value *old_value = bpf_map_lookup_elem(&overseer_stats, &key);
	if (old_value) {
		v.pkts += old_value->pkts;
		v.bytes += old_value->bytes;
	} else {
		send_event(skb, key, EVENT_NEW);
	}

	if (bpf_map_update_elem(&overseer_stats, &key, &v, BPF_ANY) != 0) {
		send_event(skb, key, EVENT_FAILED);
	}
}

__always_inline
int overseer(struct __sk_buff *skb, __u8 direction) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	void *offset = data;

	// Get the ethernet header
	struct ethhdr *ethhdr = (struct ethhdr *)offset;
	if (ethhdr + 1 > (struct ethhdr *)data_end)
		return TC_ACT_OK;
	offset = ethhdr + 1;

	// Only work with IPv4 packets for now
	if (ethhdr->h_proto != bpf_ntohs(ETH_P_IP))
		return TC_ACT_OK;

	// Get the IP packet header
	struct iphdr *iphdr = (struct iphdr *)offset;
	if (iphdr + 1 > (struct iphdr *)data_end)
		return TC_ACT_OK;
	offset = iphdr + 1;

	if (direction == DIR_INGRESS) {
		// Ingress from lan, look for the source mac and IP
		update_stats(skb, direction, iphdr->saddr, ethhdr->h_source);
	} else {
		// Egress look for traffic sent to the LAN
		update_stats(skb, direction, iphdr->daddr, ethhdr->h_dest);
	}

	return TC_ACT_OK;
}

SEC("tc/overseer_ingress")
int overseer_ingress(struct __sk_buff *skb)
{
	return overseer(skb, DIR_INGRESS);
}

SEC("tc/overseer_egress")
int overseer_egress(struct __sk_buff *skb)
{
	return overseer(skb, DIR_EGRESS);
}

char __license[] SEC("license") = "Dual MIT/GPL";
