#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "main.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("xdp")
int handle_xdp(struct xdp_md *ctx) {
    struct event_t event = {};

    // 通过指针操作解析数据包
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 从 IP 首部中过滤协议类型，只处理 ICMP 协议
    if ((data + ETH_HLEN + sizeof(struct iphdr)) > data_end)
        return XDP_PASS;
    struct iphdr *ip_hdr = data + ETH_HLEN;
    if (ip_hdr->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    u64 flags = BPF_F_CURRENT_CPU;
    u64 pkt_len = (u64)(data_end - data);
    flags |= pkt_len << 32;
    bpf_perf_event_output(ctx, &events, flags, &event, sizeof(event));

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
