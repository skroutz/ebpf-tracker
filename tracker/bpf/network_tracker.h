// SPDX-License-Identifier: GPL-2.0
#pragma once

#define TASK_COMM_LEN 16
#define AF_INET  2
#define AF_INET6 10

enum proto {
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
    __u8  proto;   // PROTO_TCP or PROTO_UDP
    __u8  af;      // AF_INET or AF_INET6
    char  comm[TASK_COMM_LEN];
};
