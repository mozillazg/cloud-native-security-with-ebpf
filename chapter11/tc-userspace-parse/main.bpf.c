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
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 从 IP 首部中过滤协议类型，只处理 ICMP 协议
    if ((data + ETH_HLEN + sizeof(struct iphdr)) > data_end)
        return;
    struct iphdr *ip_hdr = data + ETH_HLEN;
    if (ip_hdr->protocol != IPPROTO_ICMP)
        return;

    if (is_ingress) {
        event.is_ingress = 1;
    } else {
        event.is_ingress = 0;
    }

    u64 flags = BPF_F_CURRENT_CPU;
    // skb->len 数据包长度
    // save_size 用于指定存储数据包中前多少字节的数据
    u64 save_size = (u64)(skb->len);
    flags |= save_size << 32;
    bpf_perf_event_output(skb, &events, flags, &event, sizeof(event));
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
