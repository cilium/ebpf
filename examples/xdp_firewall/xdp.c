// +build ignore

#include "bpf_endian.h"
#include "common.h"

// protocols
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>


// network functions
#include <arpa/inet.h>
#include <netinet/in.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32);   // source IPv4 address
	__type(value, __u32); // (optional can be used to map a port <-> address)
} xdp_address SEC(".maps");

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	// retrieve the data from the xdp context (i.e. the packet)
    void *data_end = (void *)(long)ctx->data_end; // length/amount of data
	void *data     = (void *)(long)ctx->data; // the actual data itself
	
	struct ethhdr *eth = data; // represent the data as an ethernet frame

	// (check) make sure that the data isn't longer than the data size
    if ((void*)eth + sizeof(*eth) > data_end) { 
        return XDP_PASS;
    }

	// (check) look at the protocol within the ethernet frame, is it IP?
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return XDP_PASS;
	}

	// Create an IP packet from the data AFTER the ethernet header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

	// Create some variables to hold some information about the packet
	// int dest_port = 0;
	// int source_port = 0;

	// Look inside the IP header to determine the protocol
	// We will then strip the header and create a new variable of the remaining data
    if (ip->protocol == IPPROTO_TCP) {
	    struct tcphdr *tcp = (void*)ip + sizeof(*ip);
    	if ((void*)tcp + sizeof(*tcp) > data_end) {
    	    return XDP_PASS;
    	}
		//dest_port = ntohs(tcp->dest);
		//source_port = ntohs(tcp->source);
		//bpf_printk("SRC => %pI4 DEST => %pI4 ", &ip->saddr, &ip->daddr);
		//bpf_printk("Ports [%d => %d]", dest_port, source_port);
	} else if (ip->protocol == IPPROTO_UDP) {
    	struct udphdr *udp = (void*)ip + sizeof(*ip);
    	if ((void*)udp + sizeof(*udp) > data_end) {
    	    return XDP_PASS;
    	}
		//dest_port = ntohs(udp->dest);
		//bpf_printk("SRC => %pI4 DEST => %pI4 DestPort => %d", &ip->saddr, &ip->daddr,  dest_port);

	} else if (ip->protocol == IPPROTO_ICMP) {
		struct icmphdr *ihdr = (void*)ip + sizeof(*ip);
		if ((void*)ihdr + sizeof(*ihdr) > data_end) {
    	    return XDP_PASS;
    	}

		// change address to network byte order
		__u32 addressnethost = htonl(ip->saddr);

		// Look within the map to see if this IP address exists
		__u32 *address = bpf_map_lookup_elem(&xdp_address, &addressnethost);
	 	if (address) {
			bpf_printk("[DROP PING] from %pI4, ICMP type = %d", &ip->saddr, ihdr->type);
			return XDP_DROP;
		}
		bpf_printk("[ALLOW PING] -> from %pI4, ICMP type = %d", &ip->saddr, ihdr->type);
	}
	return XDP_PASS;
}

