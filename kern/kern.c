#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES 256

struct key {
	__be32 ip;
	__u32 ifindex;
	unsigned char macaddr[ETH_ALEN];
	__u8 padding[2];
};

struct value {
	__u64 pkts;
	__u64 bytes;
};

struct event {
	struct key key;
	unsigned char msg[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct key));
	__uint(value_size, sizeof(struct value));
	__uint(max_entries, MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} stats SEC(".maps");

SEC("xdp.frags")
int overseer(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	void *offset = data;

	// Get the ethernet header
	struct ethhdr *ethhdr = (struct ethhdr *)offset;
	if (ethhdr + 1 > (struct ethhdr *)data_end)
		return XDP_PASS;
	offset = ethhdr + 1;

	// Only work with IPv4 packets for now
	if (ethhdr->h_proto != bpf_ntohs(ETH_P_IP))
		return XDP_PASS;

	// Get the IP packet header
	struct iphdr *iphdr = (struct iphdr *)offset;
	if (iphdr + 1 > (struct iphdr *)data_end)
		return XDP_PASS;
	offset = iphdr + 1;

	struct key key = {0};
	key.ip = iphdr->saddr;
	key.ifindex = ctx->ingress_ifindex;
	__builtin_memcpy(&key.macaddr, ethhdr->h_source, ETH_ALEN);

	struct value v = {
		.pkts = 1,
		.bytes = bpf_xdp_get_buff_len(ctx),
	};

	struct value *old_value = bpf_map_lookup_elem(&stats, &key);
	if (old_value) {
		v.pkts += old_value->pkts;
		v.bytes += old_value->bytes;
	} else {
		struct event e = { .key = key, .msg = "New entry" };
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	}

	if (bpf_map_update_elem(&stats, &key, &v, BPF_ANY) != 0) {
		struct event e = { .key = key, .msg = "Failed to add entry" };
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
		return XDP_PASS;
	}

	return XDP_PASS;
}

SEC("xdp.frags")
int dummy_pass(struct xdp_md *ctx) {
	return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
