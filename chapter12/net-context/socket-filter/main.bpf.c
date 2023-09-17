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

SEC("socket")
int socket_filter_icmp(struct __sk_buff *skb) {
    struct event_t event = {};

    // 过滤以太网Ethernet II帧的数据类型，只处理 ETH_P_IP 类型
    struct ethhdr eth_hdr;
    if (bpf_skb_load_bytes(skb, 0, &eth_hdr, sizeof(eth_hdr)) < 0)
        return 0;
    if (bpf_ntohs(eth_hdr.h_proto) != ETH_P_IP)
        return 0;

    // 从 IP 首部中过滤协议类型，只处理 ICMP 协议
    struct iphdr ip_hdr;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip_hdr, sizeof(ip_hdr)) < 0)
        return 0;
    if (ip_hdr.protocol != IPPROTO_ICMP)
        return 0;

    event.src_addr = ip_hdr.saddr;
    event.dst_addr = ip_hdr.daddr;

    // 解析 ICMP 消息
    struct icmphdr icmp_hdr;
    if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct iphdr), &icmp_hdr, sizeof(icmp_hdr)) < 0)
        return 0;

    event.type = icmp_hdr.type;
    event.code = icmp_hdr.code;

    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char _license[] SEC("license") = "GPL";
