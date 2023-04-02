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

static __always_inline void handle_skb(struct __sk_buff *skb, bool is_ingress) {
    struct event_t event = {};

    // 通过指针操作解析数据包
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // 从 IP 首部中过滤协议类型，只处理 ICMP 协议
    if ((data + ETH_HLEN + sizeof(struct iphdr)) > data_end)
        return;
    struct iphdr *ip_hdr = data + ETH_HLEN;
    if (ip_hdr->protocol != IPPROTO_ICMP)
        return;

    // 解析 ICMP 消息
    if ((data + ETH_HLEN + sizeof(struct iphdr) + sizeof(struct icmphdr)) > data_end)
        return;
    struct icmphdr *icmp_hdr = (void *)ip_hdr + sizeof(struct iphdr);

    if (is_ingress) {
        event.is_ingress = 1;
    } else {
        event.is_ingress = 0;
    }
    event.src_addr = ip_hdr->saddr;
    event.dst_addr = ip_hdr->daddr;
    event.type = icmp_hdr->type;
    event.code = icmp_hdr->code;

    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

SEC("tc")
int on_ingress(struct __sk_buff *skb) {
    handle_skb(skb, true);
    return TC_ACT_UNSPEC;
}

SEC("tc")
int on_egress(struct __sk_buff *skb) {
    handle_skb(skb, false);
    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
