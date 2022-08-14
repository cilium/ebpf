#ifndef TCPRTT_SOCKOPS_H
#define TCPRTT_SOCKOPS_H

#define AF_INET 2
#define SOCKOPS_MAP_SIZE 65535

enum {
	SOCK_TYPE_ACTIVE = 0,
	SOCK_TYPE_PASSIVE = 1,
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SOCKOPS_MAP_SIZE);
	__type(key, struct sk_key);
	__type(value, struct sk_info);
} map_estab_sk SEC(".maps");

struct sk_key {
	u32 local_ip4;
	u32 remote_ip4;
	u32 local_port;
	u32 remote_port;
};

struct sk_info {
	struct sk_key sk_key;
	u8 sk_type;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} rtt_events SEC(".maps");

struct rtt_event {
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
    u32 srtt;
	u8 sk_type;
};
struct rtt_event *unused_event __attribute__((unused));

#endif