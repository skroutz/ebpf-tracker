// SPDX-License-Identifier: GPL-2.0
#pragma once

#define TASK_COMM_LEN 16
#define AF_INET  2
#define AF_INET6 10

enum net_proto {
    PROTO_TCP = 6,
    PROTO_UDP = 17,
};

struct net_event {
    __u64 timestamp_ns;
    __u32 src_ip4;
    __u32 dst_ip4;
    __u8  src_ip6[16];
    __u8  dst_ip6[16];
    __u16 src_port;
    __u16 dst_port;
    __u32 pid;
    __u32 uid;
    __s32 ret;     // kernel return value (TCP: 0/-EINPROGRESS/error; UDP: always 0)
    __u8  proto;   // PROTO_TCP or PROTO_UDP
    __u8  af;      // AF_INET or AF_INET6
    char  comm[TASK_COMM_LEN];
};

// Key for per-flow UDP deduplication map. All bytes must be zeroed before use
// so the map key comparison is deterministic (no padding byte surprises).
struct udp_dedup_key {
    __u32 pid;
    __u32 dst_ip4;   // non-zero for AF_INET; zero for AF_INET6
    __u8  dst_ip6[16];
    __u16 dst_port;
    __u8  af;
    __u8  _pad;
};
