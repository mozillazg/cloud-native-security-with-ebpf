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

    return XDP_PASS;
}

SEC("xdp")
int handle_xdp_tcp(struct xdp_md *ctx) {

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if ((data + ETH_HLEN + sizeof(struct iphdr)) > data_end) // not ip
        return XDP_PASS;
    struct iphdr *ip_hdr = data + ETH_HLEN;
    if (ip_hdr->protocol != IPPROTO_TCP)  // not tcp
        return XDP_PASS;

    if (data + ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    struct tcphdr *tcp_hdr = data + ETH_HLEN + sizeof(struct iphdr);

    u32 saddr = ip_hdr->saddr;
    u32 daddr = ip_hdr->daddr;
    u32 dest = bpf_htons(tcp_hdr->dest);

    bpf_printk("saddr: %pI4, daddr: %pI4:%d", &saddr, &daddr, dest);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
