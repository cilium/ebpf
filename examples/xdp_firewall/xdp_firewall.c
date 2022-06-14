// +build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define BPF_F_NO_PREALLOC 1

struct lpm_trie_key {
	u32 prefixlen;
	u8 addr[4];
};

struct bpf_map_def SEC("maps") xdp_map = {
	.type        = BPF_MAP_TYPE_LPM_TRIE,
	.key_size    = sizeof(struct lpm_trie_key),
	.value_size  = sizeof(u64),
	.max_entries = 1 << 10,
	.map_flags   = BPF_F_NO_PREALLOC,
};

SEC("xdp")
int xdp_drop_packet(struct xdp_md *ctx) {
	void *data     = (void *)(unsigned long)ctx->data;
	void *data_end = (void *)(unsigned long)ctx->data_end;
	if (data + sizeof(struct ethhdr) > data_end) { // skip non ethernet frames
		return XDP_PASS;
	}

	struct ethhdr *eth_hdr = data;
	if (eth_hdr->h_proto != bpf_htons(ETH_P_IP)) { // skip non IPv4 frames
		return XDP_PASS;
	}

	data                   = data + sizeof(struct ethhdr);
	struct iphdr *ipv4_hdr = data;
	if (data + sizeof(struct iphdr) > data_end) { // drop invalid IPv4 packets
		return XDP_DROP;
	}

	u64 *drop_count;
	struct lpm_trie_key key;
	key.prefixlen = 32;
	key.addr[0]   = ipv4_hdr->saddr & 0xff;
	key.addr[1]   = (ipv4_hdr->saddr >> 8) & 0xff;
	key.addr[2]   = (ipv4_hdr->saddr >> 16) & 0xff;
	key.addr[3]   = (ipv4_hdr->saddr >> 24) & 0xff;

	drop_count = bpf_map_lookup_elem(&xdp_map, &key);
	if (drop_count) { // source IP in block list, drop it
		__sync_fetch_and_add(drop_count, 1);
		return XDP_DROP;
	}

	return XDP_PASS;
}
