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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} modify_map SEC(".maps");


SEC("tc")
int on_egress(struct __sk_buff *skb) {
    bpf_skb_pull_data(skb, 0);
    // 通过指针操作解析数据包
    void *data_end = (void *)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;

    // 从 IP 首部中过滤协议类型，只处理 TCP 协议
    struct iphdr *ip_hdr = data + ETH_HLEN;
    if ((void *)ip_hdr + sizeof(struct iphdr) > data_end) {
        return TC_ACT_UNSPEC;
    }
    if (ip_hdr->protocol != IPPROTO_TCP) {
        return TC_ACT_UNSPEC;
    }

    // TCP 协议数据过滤
    struct tcphdr *tcp_hdr = (void *)ip_hdr + sizeof(struct iphdr);
    if ((void *)tcp_hdr + sizeof(struct tcphdr) > data_end) {
        return TC_ACT_UNSPEC;
    }
    if (tcp_hdr->dest != bpf_htons(8000)) {
        bpf_printk("skip port: %d", bpf_ntohs(tcp_hdr->dest));
        return TC_ACT_UNSPEC;
    }

    // 防止重复劫持，出现一直重传
    int zero = 0;
    if (bpf_map_lookup_elem(&modify_map, &tcp_hdr->source)) {
        bpf_printk("exist");
        return TC_ACT_UNSPEC;
    }
    bpf_map_update_elem(&modify_map, &tcp_hdr->source, &zero, BPF_ANY);
    bpf_printk("hijack start");

    unsigned int old_payload_size = bpf_htons(ip_hdr->tot_len) - (tcp_hdr->doff * 4) - sizeof(struct iphdr);
    char new_payload[64];
    char replace[] = "[password: test]";
    __builtin_memcpy(new_payload, replace, 64);
    bpf_printk("tc: will send new payload: %s", new_payload);
    unsigned int new_payload_size = sizeof(new_payload);
    u32 increment_len = new_payload_size - old_payload_size;

    u16 old_dest_port = tcp_hdr->dest;
    u32 old_dest_addr = ip_hdr->daddr;

    // 替换 IP 首部，修改目的 IP
    u32 new_dest_addr = ip_to_u32(127, 0, 0, 1);
    u32 dest_addr_offset = ETH_HLEN + offsetof(struct iphdr, daddr);
    u32 ip_checksum_offset = ETH_HLEN + offsetof(struct iphdr, check);
    int ret = bpf_skb_store_bytes(skb, dest_addr_offset, &new_dest_addr, sizeof(u32), 0);
    if (ret < 0) {
        bpf_printk("replace dest addr failed: %d", ret);
        return TC_ACT_UNSPEC;
    }
    // 重新计算 IP 首部 checksum
    ret = bpf_l3_csum_replace(skb, ip_checksum_offset, old_dest_addr, new_dest_addr, sizeof(u32));
    if (ret < 0) {
        bpf_printk("bpf_l3_csum_replace failed: %d", ret);
        return TC_ACT_UNSPEC;
    }

    // 替换 TCP 首部，修改目的端口
    u16 new_dest_port = bpf_htons(9090);
    u32 dest_port_offset = ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest);
    u32 tcp_checksum_offset = ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check);

    ret = bpf_skb_store_bytes(skb, dest_port_offset, &new_dest_port, sizeof(u16), 0);
    if (ret < 0) {
        bpf_printk("replace dest port failed: %d", ret);
        return TC_ACT_UNSPEC;
    }
    // 重新计算 TCP 首部 checksum
    ret = bpf_l4_csum_replace(skb, tcp_checksum_offset, old_dest_port, new_dest_port, sizeof(u16));
    if (ret < 0) {
        bpf_printk("bpf_l4_csum_replace failed: %d", ret);
        return TC_ACT_UNSPEC;
    }

    // 调整 skb 关联的数据包长度信息
    ret = bpf_skb_change_tail(skb, skb->len+increment_len, 0);
    if (ret < 0) {
        bpf_printk("bpf_skb_change_tail failed: %d", ret);
        return TC_ACT_UNSPEC;
    }
    ret = bpf_skb_pull_data(skb, 0);
    if (ret < 0) {
        bpf_printk("bpf_skb_pull_data failed: %d", ret);
        return TC_ACT_UNSPEC;
    }

    // 调用 bpf_skb_change_tail 后，需要重新执行检查，否则验证器会验证失败
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    ip_hdr = data + ETH_HLEN;
    if ((void *)ip_hdr + sizeof(struct iphdr) > data_end) {
        return TC_ACT_UNSPEC;
    }
    if (ip_hdr->protocol != IPPROTO_TCP) {
        return TC_ACT_UNSPEC;
    }
    tcp_hdr = (void *)ip_hdr + sizeof(struct iphdr);
    if ((void *)tcp_hdr + sizeof(struct tcphdr) > data_end) {
        return TC_ACT_UNSPEC;
    }

    // 替换 TCP payload
    u32 offset = ETH_HLEN + sizeof(struct iphdr) + (tcp_hdr->doff * 4);
    ret = bpf_skb_store_bytes(skb, offset, new_payload, sizeof(new_payload), 0);
    if (ret < 0) {
        bpf_printk("overwrite payload failed: %d", ret);
        return TC_ACT_UNSPEC;
    }

    bpf_printk("hijack end");

    return TC_ACT_UNSPEC;
}


SEC("xdp")
int handle_xdp(struct xdp_md *ctx) {
    int target_port = 9090;

    // 通过指针操作解析数据包
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 从 IP 首部中过滤协议类型，只处理 TCP 协议
    struct iphdr *ip_hdr = data + ETH_HLEN;
    if ((void *)ip_hdr + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }
    if (ip_hdr->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    // TCP 协议数据过滤
    struct tcphdr *tcp_hdr = (void *)ip_hdr + sizeof(struct iphdr);
    if ((void *)tcp_hdr + sizeof(struct tcphdr) > data_end) {
        return XDP_PASS;
    }
    if (tcp_hdr->dest != bpf_htons(target_port)) {
        return XDP_PASS;
    }


    // 从 SYN 包中读取数据
    bpf_printk("xdp syn: %d", tcp_hdr->syn);
    if (tcp_hdr->syn == 1) {
        char content[64];
        char *payload = (void *)tcp_hdr + tcp_hdr->doff * 4;
        bpf_probe_read_kernel(&content, sizeof(content), payload);
        bpf_printk("xdp: received payload: %s", content);
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
