// SPDX-License-Identifier: GPL-2.0
// BPF CO-RE network tracker: TCP connect + UDP send/recv

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "network_tracker.h"

// vmlinux.h does not export errno constants; define the ones we need.
#ifndef EINVAL
#define EINVAL          22
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT    97
#endif

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); // 4 MiB
} events SEC(".maps");

// LRU hash for UDP per-flow deduplication.
// Suppresses repeated events for the same (pid, dst_ip, dst_port) within
// UDP_DEDUP_NS nanoseconds to avoid flooding on high-rate sockets (DNS, NTP).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct udp_dedup_key);
    __type(value, __u64); // last-emitted timestamp_ns
} udp_seen SEC(".maps");

#define UDP_DEDUP_NS 1000000000ULL  // 1 second

// ---------------------------------------------------------------------------
// TCP v4 connect — fexit
//
// fexit over kprobe gives us two things:
//  1. The kernel return value: 0 or -EINPROGRESS means the SYN was queued;
//     negative values (EHOSTUNREACH, ENETUNREACH, …) mean the kernel rejected
//     the attempt immediately. ALL outcomes are recorded — connections to
//     unreachable hosts are a key malware indicator.
//  2. The destination address read from the caller-supplied sockaddr (a
//     kernel-stack copy placed there by move_addr_to_kernel before the call).
//     A kprobe at entry reads sk->skc_daddr before the kernel sets it; fexit
//     reads the sockaddr directly, which is reliable on all code paths.
// ---------------------------------------------------------------------------

SEC("fexit/tcp_v4_connect")
int BPF_PROG(trace_tcp_v4_connect,
             struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    // Pure argument errors carry no meaningful address; skip them.
    if (ret == -EINVAL || ret == -EAFNOSUPPORT)
        return 0;

    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    __u64 pid_tgid  = bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_boot_ns();
    e->pid          = pid_tgid >> 32;
    e->uid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->proto        = PROTO_TCP;
    e->af           = AF_INET;
    e->ret          = ret;
    e->src_ip4      = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->src_port     = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // uaddr is a kernel-stack copy (move_addr_to_kernel was called before
    // tcp_v4_connect), so bpf_probe_read_kernel is correct here.
    struct sockaddr_in sa4;
    __builtin_memset(&sa4, 0, sizeof(sa4));
    if (bpf_probe_read_kernel(&sa4, sizeof(sa4), uaddr) == 0) {
        e->dst_ip4  = sa4.sin_addr.s_addr;
        e->dst_port = bpf_ntohs(sa4.sin_port);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// TCP v6 connect — fexit
// ---------------------------------------------------------------------------

SEC("fexit/tcp_v6_connect")
int BPF_PROG(trace_tcp_v6_connect,
             struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    if (ret == -EINVAL || ret == -EAFNOSUPPORT)
        return 0;

    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    __u64 pid_tgid  = bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_boot_ns();
    e->pid          = pid_tgid >> 32;
    e->uid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->proto        = PROTO_TCP;
    e->af           = AF_INET6;
    e->ret          = ret;
    BPF_CORE_READ_INTO(&e->src_ip6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    e->src_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct sockaddr_in6 sa6;
    __builtin_memset(&sa6, 0, sizeof(sa6));
    if (bpf_probe_read_kernel(&sa6, sizeof(sa6), uaddr) == 0) {
        __builtin_memcpy(e->dst_ip6, sa6.sin6_addr.in6_u.u6_addr8, 16);
        e->dst_port = bpf_ntohs(sa6.sin6_port);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// UDP v4 sendmsg — fentry with per-flow deduplication
//
// Connected sockets: destination in sk->skc_daddr / skc_dport.
// Unconnected sockets (e.g. DNS queries): destination in msg->msg_name.
//
// Pointer type of msg_name depends on the syscall path:
//   sendto()  → __sys_sendto calls move_addr_to_kernel() first, so msg_name
//               is a kernel stack pointer by the time udp_sendmsg is called.
//   sendmsg() → copy_msghdr_from_user() leaves msg_name as the original
//               userspace pointer (move_addr_to_kernel is NOT called first).
//
// We try bpf_probe_read_kernel first; if it fails or produces a non-AF_INET
// family, we retry with bpf_probe_read_user. sin_family == AF_INET acts as a
// sanity check to distinguish a successful read from a failed one that
// returned a zeroed buffer.
// ---------------------------------------------------------------------------

SEC("fentry/udp_sendmsg")
int BPF_PROG(trace_udp_sendmsg,
             struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 dst_ip4  = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    // Unconnected UDP socket — read destination from msg->msg_name.
    if (!dst_ip4) {
        void *msg_name = BPF_CORE_READ(msg, msg_name);
        if (msg_name) {
            struct sockaddr_in sa4;
            __builtin_memset(&sa4, 0, sizeof(sa4));
            // sendto() path: msg_name is a kernel pointer.
            if (bpf_probe_read_kernel(&sa4, sizeof(sa4), msg_name) != 0 ||
                sa4.sin_family != AF_INET) {
                // sendmsg() path: msg_name is still a userspace pointer.
                __builtin_memset(&sa4, 0, sizeof(sa4));
                bpf_probe_read_user(&sa4, sizeof(sa4), msg_name);
            }
            if (sa4.sin_family == AF_INET) {
                dst_ip4  = sa4.sin_addr.s_addr;
                dst_port = bpf_ntohs(sa4.sin_port);
            }
        }
    }
    if (!dst_ip4)
        return 0;

    // Dedup: emit at most once per second per (pid, dst_ip, dst_port).
    struct udp_dedup_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.pid      = pid_tgid >> 32;
    key.af       = AF_INET;
    key.dst_ip4  = dst_ip4;
    key.dst_port = dst_port;

    __u64 now  = bpf_ktime_get_boot_ns();
    __u64 *last = bpf_map_lookup_elem(&udp_seen, &key);
    if (last && (now - *last) < UDP_DEDUP_NS)
        return 0;
    bpf_map_update_elem(&udp_seen, &key, &now, BPF_ANY);

    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp_ns = now;
    e->pid          = pid_tgid >> 32;
    e->uid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->proto        = PROTO_UDP;
    e->af           = AF_INET;
    e->ret          = 0;
    e->src_ip4      = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->dst_ip4      = dst_ip4;
    e->src_port     = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    e->dst_port     = dst_port;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// UDP v4 recvmsg — fentry with per-flow deduplication
// Only connected sockets have sk->skc_daddr populated; skip the rest.
// ---------------------------------------------------------------------------

SEC("fentry/udp_recvmsg")
int BPF_PROG(trace_udp_recvmsg,
             struct sock *sk, struct msghdr *msg, size_t len, int flags,
             int *addr_len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 dst_ip4  = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (!dst_ip4)
        return 0;

    struct udp_dedup_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.pid      = pid_tgid >> 32;
    key.af       = AF_INET;
    key.dst_ip4  = dst_ip4;
    key.dst_port = dst_port;

    __u64 now  = bpf_ktime_get_boot_ns();
    __u64 *last = bpf_map_lookup_elem(&udp_seen, &key);
    if (last && (now - *last) < UDP_DEDUP_NS)
        return 0;
    bpf_map_update_elem(&udp_seen, &key, &now, BPF_ANY);

    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp_ns = now;
    e->pid          = pid_tgid >> 32;
    e->uid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->proto        = PROTO_UDP;
    e->af           = AF_INET;
    e->ret          = 0;
    e->src_ip4      = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->dst_ip4      = dst_ip4;
    e->src_port     = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    e->dst_port     = dst_port;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// UDPv6 sendmsg / recvmsg — kept as kprobes for portability; these functions
// may not exist on all kernel configurations.  Best-effort attach in main.go.
// Deduplication is applied via the shared udp_seen map.
// ---------------------------------------------------------------------------

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(trace_udpv6_sendmsg, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u8 dst_ip6[16];
    BPF_CORE_READ_INTO(&dst_ip6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    __u16 dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    // Skip unconnected sockets (no cached peer address).
    __u64 hi, lo;
    __builtin_memcpy(&hi, dst_ip6,     8);
    __builtin_memcpy(&lo, dst_ip6 + 8, 8);
    if (!hi && !lo)
        return 0;

    struct udp_dedup_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.pid      = pid_tgid >> 32;
    key.af       = AF_INET6;
    __builtin_memcpy(key.dst_ip6, dst_ip6, 16);
    key.dst_port = dst_port;

    __u64 now  = bpf_ktime_get_boot_ns();
    __u64 *last = bpf_map_lookup_elem(&udp_seen, &key);
    if (last && (now - *last) < UDP_DEDUP_NS)
        return 0;
    bpf_map_update_elem(&udp_seen, &key, &now, BPF_ANY);

    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp_ns = now;
    e->pid          = pid_tgid >> 32;
    e->uid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->proto        = PROTO_UDP;
    e->af           = AF_INET6;
    e->ret          = 0;
    BPF_CORE_READ_INTO(&e->src_ip6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    __builtin_memcpy(e->dst_ip6, dst_ip6, 16);
    e->src_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    e->dst_port = dst_port;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/udpv6_recvmsg")
int BPF_KPROBE(trace_udpv6_recvmsg, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u8 dst_ip6[16];
    BPF_CORE_READ_INTO(&dst_ip6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    __u16 dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    __u64 hi, lo;
    __builtin_memcpy(&hi, dst_ip6,     8);
    __builtin_memcpy(&lo, dst_ip6 + 8, 8);
    if (!hi && !lo)
        return 0;

    struct udp_dedup_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.pid      = pid_tgid >> 32;
    key.af       = AF_INET6;
    __builtin_memcpy(key.dst_ip6, dst_ip6, 16);
    key.dst_port = dst_port;

    __u64 now  = bpf_ktime_get_boot_ns();
    __u64 *last = bpf_map_lookup_elem(&udp_seen, &key);
    if (last && (now - *last) < UDP_DEDUP_NS)
        return 0;
    bpf_map_update_elem(&udp_seen, &key, &now, BPF_ANY);

    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp_ns = now;
    e->pid          = pid_tgid >> 32;
    e->uid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->proto        = PROTO_UDP;
    e->af           = AF_INET6;
    e->ret          = 0;
    BPF_CORE_READ_INTO(&e->src_ip6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    __builtin_memcpy(e->dst_ip6, dst_ip6, 16);
    e->src_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    e->dst_port = dst_port;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
