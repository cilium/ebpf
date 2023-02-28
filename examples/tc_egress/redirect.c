#include "common.h"
#include "bpf_endian.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT -1
#define ETH_P_IP 0x0800
#define MAX_ENTRIES 64
#define AF_INET		2

char __license[] SEC("license") = "Dual MIT/GPL";

struct ipv4_map_record  {
    u32 interfaceID;
    u32 nextHop;
};

struct bpf_map_def SEC("maps") redirect_map_ipv4 = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(struct ipv4_map_record),
	.max_entries = MAX_ENTRIES,
};

SEC("tc_redirect")
int redirect(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct bpf_redir_neigh neighInfo = {0};

    u32 key = 0;
	struct ipv4_map_record *nextHop = 0;

    iph = data + sizeof(*eth);

    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    key = bpf_ntohl(iph->saddr);
    nextHop = bpf_map_lookup_elem(&redirect_map_ipv4, &key);    
    if (nextHop != NULL) {
        neighInfo.ipv4_nh = bpf_htonl(nextHop->nextHop);
        neighInfo.nh_family = AF_INET;
        return bpf_redirect_neigh(nextHop->interfaceID, &neighInfo, sizeof(neighInfo), 0);
    }
    return TC_ACT_OK;
}
