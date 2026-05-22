// SPDX-License-Identifier: GPL-2.0
// BPF CO-RE network tracker: TCP connect + UDP send/recv

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "network_tracker.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); // 4 MiB
} events SEC(".maps");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static __always_inline void fill_common(struct net_event *e)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid          = pid_tgid >> 32;
    e->uid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->timestamp_ns = bpf_ktime_get_boot_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline void submit_tcp4(struct sock *sk)
{
    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    fill_common(e);
    e->proto     = PROTO_TCP;
    e->af        = AF_INET;
    e->src_ip4   = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->dst_ip4   = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->src_port  = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    e->dst_port  = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_ringbuf_submit(e, 0);
}

static __always_inline void submit_tcp6(struct sock *sk)
{
    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    fill_common(e);
    e->proto    = PROTO_TCP;
    e->af       = AF_INET6;
    BPF_CORE_READ_INTO(&e->src_ip6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(&e->dst_ip6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    e->src_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    e->dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_ringbuf_submit(e, 0);
}

// ---------------------------------------------------------------------------
// TCP v4 connect
// ---------------------------------------------------------------------------

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect, struct sock *sk)
{
    submit_tcp4(sk);
    return 0;
}

// ---------------------------------------------------------------------------
// TCP v6 connect
// ---------------------------------------------------------------------------

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(trace_tcp_v6_connect, struct sock *sk)
{
    submit_tcp6(sk);
    return 0;
}

// ---------------------------------------------------------------------------
// UDP sendmsg  (captures outgoing UDP)
// ---------------------------------------------------------------------------

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk)
{
    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e);
    e->proto    = PROTO_UDP;
    e->af       = AF_INET;
    e->src_ip4  = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->dst_ip4  = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->src_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    e->dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// UDP recvmsg  (captures incoming UDP)
// ---------------------------------------------------------------------------

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(trace_udp_recvmsg, struct sock *sk)
{
    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e);
    e->proto    = PROTO_UDP;
    e->af       = AF_INET;
    e->src_ip4  = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->dst_ip4  = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->src_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    e->dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// UDPv6 sendmsg / recvmsg
// ---------------------------------------------------------------------------

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(trace_udpv6_sendmsg, struct sock *sk)
{
    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e);
    e->proto    = PROTO_UDP;
    e->af       = AF_INET6;
    BPF_CORE_READ_INTO(&e->src_ip6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(&e->dst_ip6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    e->src_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    e->dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/udpv6_recvmsg")
int BPF_KPROBE(trace_udpv6_recvmsg, struct sock *sk)
{
    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e);
    e->proto    = PROTO_UDP;
    e->af       = AF_INET6;
    BPF_CORE_READ_INTO(&e->src_ip6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(&e->dst_ip6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    e->src_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    e->dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
