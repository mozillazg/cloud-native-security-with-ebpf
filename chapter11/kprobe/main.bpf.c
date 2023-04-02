#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "main.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct sock *);
} socks SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect, struct sock *sk) {
    u64 tid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&socks, &tid, &sk, BPF_ANY);

    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kretprobe_tcp_v4_connect) {
    struct event_t event = {};
    struct sock **sk_pp;
    struct sock *sk;
    u64 tid = bpf_get_current_pid_tgid();

    sk_pp = bpf_map_lookup_elem(&socks, &tid);
    if (!sk_pp)
        return 0;
    sk = *sk_pp;

    // 源地址
    BPF_CORE_READ_INTO(&event.src_addr, sk, __sk_common.skc_rcv_saddr);
    // 源端口
    BPF_CORE_READ_INTO(&event.src_port, sk, __sk_common.skc_num);
    // 目标地址
    BPF_CORE_READ_INTO(&event.dst_addr, sk, __sk_common.skc_daddr);
    // 目标端口
    BPF_CORE_READ_INTO(&event.dst_port, sk, __sk_common.skc_dport);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    bpf_map_delete_elem(&socks, &tid);

    return 0;
}

char _license[] SEC("license") = "GPL";
