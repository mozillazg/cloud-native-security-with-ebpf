#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define ETH_HLEN    14         /* Total octets in header.   */


SEC("socket")
int socket_filter_all(struct __sk_buff *skb) {
    return -1;
}


SEC("socket")
int socket_filter_icmp(struct __sk_buff *skb) {
    u8 protocol;
    // 只处理 ICMP 协议
    if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), &protocol, sizeof(protocol)) < 0)
        return 0;
    if (protocol != IPPROTO_ICMP)
        return 0;

    int size = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct icmphdr);
    return size;
}

char _license[] SEC("license") = "GPL";
