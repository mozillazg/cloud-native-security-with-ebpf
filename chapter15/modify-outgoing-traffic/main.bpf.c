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
    int target_port = 8080;

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
//    if (tcp_hdr->dest != bpf_htons(target_port)) {
//        return TC_ACT_UNSPEC;
//    }

    char replace[] = "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: curl/7.81.0\r\n";
    int replace_size = 25;
    char *payload = (void *)tcp_hdr + tcp_hdr->doff * 4;
    unsigned int payload_size = bpf_htons(ip_hdr->tot_len) - (tcp_hdr->doff * 4) - sizeof(struct iphdr);
//    if (payload_size < 25) {
//        return TC_ACT_UNSPEC;
//    }


    int zero = 0;
    if (bpf_map_lookup_elem(&modify_map, &zero)) {
        bpf_printk("exist");
        return TC_ACT_UNSPEC;
    }
    bpf_map_update_elem(&modify_map, &zero, &zero, BPF_ANY);
    bpf_printk("update");

    char content[100];
    bpf_probe_read_kernel(&content, sizeof(content), payload);
    bpf_printk("tcp: payload: %s", content);
    char new_payload[64];
    __builtin_memcpy(new_payload, replace, 64);

//    int offset = ETH_HLEN + sizeof(struct iphdr) + tcp_hdr->doff * 4;
//    bpf_skb_store_bytes(skb, offset, &replace, sizeof(replace), BPF_F_RECOMPUTE_CSUM);

//    bpf_skb_pull_data(skb, 0);
//    bpf_printk("%x", ip_hdr->daddr);

    u32 old_dest_addr = ip_hdr->daddr;
    u16 old_dest_port = tcp_hdr->dest;
    u32 new_dest_addr = 0x100007f;
    u32 dest_addr_offset = ETH_HLEN + offsetof(struct iphdr, daddr);
    u32 ip_checksum_offset = ETH_HLEN + offsetof(struct iphdr, check);

    bpf_skb_pull_data(skb, 0);

    int ret = bpf_l3_csum_replace(skb, ip_checksum_offset, old_dest_addr, new_dest_addr, sizeof(u32));
    if (ret < 0) {
        bpf_printk("bpf_l3_csum_replace failed: %d", ret);
        return TC_ACT_UNSPEC;
    }
    ret = bpf_skb_store_bytes(skb, dest_addr_offset, &new_dest_addr, sizeof(u32), 0);
    if (ret < 0) {
        bpf_printk("replace dest addr failed: %d", ret);
        return TC_ACT_UNSPEC;
    }

    u32 increment_len = sizeof(char)*64;
    u16 new_dest_port = bpf_htons(9090);
    u32 dest_port_offset = ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest);
    u32 tcp_checksum_offset = ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check);

    ret = bpf_l4_csum_replace(skb, tcp_checksum_offset, old_dest_port, new_dest_port, sizeof(u16));
    if (ret < 0) {
        bpf_printk("bpf_l4_csum_replace failed: %d", ret);
        return TC_ACT_UNSPEC;
    }
    ret = bpf_skb_store_bytes(skb, dest_port_offset, &new_dest_port, sizeof(u16), 0);
    if (ret < 0) {
        bpf_printk("replace dest port failed: %d", ret);
        return TC_ACT_UNSPEC;
    }

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

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    // 从 IP 首部中过滤协议类型，只处理 TCP 协议
    ip_hdr = data + ETH_HLEN;
    if ((void *)ip_hdr + sizeof(struct iphdr) > data_end) {
        return TC_ACT_UNSPEC;
    }
    if (ip_hdr->protocol != IPPROTO_TCP) {
        return TC_ACT_UNSPEC;
    }
    // TCP 协议数据过滤
    tcp_hdr = (void *)ip_hdr + sizeof(struct iphdr);
    if ((void *)tcp_hdr + sizeof(struct tcphdr) > data_end) {
        return TC_ACT_UNSPEC;
    }
    payload_size = bpf_htons(ip_hdr->tot_len) - (tcp_hdr->doff * 4) - sizeof(struct iphdr);
    payload = data_end - payload_size;
    if(payload_size>=sizeof(char)*64){
        return TC_ACT_OK;
    }

    u32 offset = skb->len-payload_size-increment_len;
//    if(increment_len>skb->data_end-skb->data){
//        return TC_ACT_OK;
//    }
    if(data + increment_len > data_end){
        return TC_ACT_OK;
    }

    //Simple strlen
    u32 payload_char_len = str_len(new_payload, 64);
    if(payload_char_len>=increment_len|| payload_char_len<=0){
        return TC_ACT_OK;
    }

    bpf_printk("New payload offset %i, writing %i bytes\n", offset, payload_char_len);
    ret = bpf_skb_store_bytes(skb, offset, new_payload, payload_char_len, 0);
    if (ret < 0) {
        bpf_printk("Failed to overwrite payload: %d\n", ret);
        return TC_ACT_OK;
    }

    data = (void *)(__u64)skb->data;
    data_end = (void *)(__u64)skb->data_end;

//    eth = data;
//    if ((void *)eth + sizeof(struct ethhdr) > data_end){
//        bpf_printk("ETH\n");
//        return TC_ACT_OK;
//    }
    ip_hdr = (struct iphdr*)(data + sizeof(struct ethhdr));
    if ((void *)ip_hdr + sizeof(struct iphdr) > data_end){
        bpf_printk("IP CHECK, ip: %llx, data: %llx, datalen: %llx\n", ip_hdr, data, data_end);
        return TC_ACT_OK;
    }
    tcp_hdr = (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    if ((void *)tcp_hdr + sizeof(struct tcphdr) > data_end){
        bpf_printk("TCP CHECK\n");
        return TC_ACT_OK;
    }

    //Fixing IP checksum
    //bpf_printk("Old value %x, new value %x\n", htons(ip->tot_len), htons(ntohs(ip->tot_len)+increment_len));
    u32 offset_ip_tot_len = offsetof(struct iphdr, tot_len)+ sizeof(struct ethhdr);
    u16 new_tot_len = bpf_htons(bpf_ntohs(ip_hdr->tot_len)+increment_len);
    ret = bpf_l3_csum_replace(skb, ip_checksum_offset, (ip_hdr->tot_len), new_tot_len, sizeof(__u16));
    if (ret < 0) {
        bpf_printk("Failed to recompute l3 checksum: %d\n", ret);
        return TC_ACT_OK;
    }
    bpf_printk("New ip tot len: %i\n", bpf_ntohs(new_tot_len));
    ret = bpf_skb_store_bytes(skb, offset_ip_tot_len, &new_tot_len, sizeof(__u16), 0);
    if (ret < 0) {
        bpf_printk("Failed to overwrite ip total len: %d\n", ret);
        return TC_ACT_OK;
    }

    bpf_printk("Finished packet hijacking routine\n");

    return TC_ACT_OK;
}


SEC("xdp")
int handle_xdp(struct xdp_md *ctx) {
    // GET /healthz HTTP/1.1\r\n
    // Host: 127.0.0.1:8080\r\n
    // User-Agent: curl/7.81.0 cmd:test\r\n
    // Accept: */*\r\n
    char keyword[] = "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: curl/7.81.0 cmd:";
    int keyword_size = 73;
    char cmd_len = 20;
    char replace[] = "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: curl/7.81.0\r\nCache-Control: no-cache";
    char replace_size = 93;
//    char keyword[] = "!!!CMD:";
//    int keyword_size = 7;
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

    // 过滤关键字
    char *payload = (void *)tcp_hdr + tcp_hdr->doff * 4;
    unsigned int payload_size = bpf_htons(ip_hdr->tot_len) - (tcp_hdr->doff * 4) - sizeof(struct iphdr);
//    if (payload_size < keyword_size + cmd_len) {
//        return XDP_PASS;
//    }
//    if ((void *)payload + keyword_size + cmd_len > data_end) {
//        return XDP_PASS;
//    }
//    if ((void *)payload + replace_size > data_end) {
//        return XDP_PASS;
//    }
//    if (!str_eq(payload, keyword, keyword_size)) {
//        return XDP_PASS;
//    }
//
//    int zero = 0;
//    struct event_t *event;
//    event = bpf_map_lookup_elem(&tmp_storage, &zero);
//    if (!event) {
//        return XDP_PASS;
//    }
//
//    event->src_addr = ip_hdr->saddr;
//    event->dest_addr = ip_hdr->daddr;
//    event->src_port = bpf_ntohs(tcp_hdr->source);
//    event->dest_port = bpf_ntohs(tcp_hdr->dest);
//
//    bpf_probe_read_kernel(&event->payload, sizeof(event->payload), payload);

//
////    bpf_printk("tcp: %x:%d ->", event->src_addr, event->src_port);
////    bpf_printk("tcp: %x:%d ", event->dest_addr, event->dest_port);
////    bpf_printk("tcp: payload: %s", event->payload);

//
//    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
//
//    // 更新数据包
//#pragma unroll
//    for (int i = 0; i < replace_size; i++) {
//        payload[i] = replace[i];
//    }
//
    bpf_printk("xdp xx: %d", tcp_hdr->syn);
    if (tcp_hdr->syn == 1) {
        char content[64];
        bpf_probe_read_kernel(&content, sizeof(content), payload);
        bpf_printk("xdp: payload: %s", content);
        bpf_printk("xdp seq: %d", tcp_hdr->seq);
        return XDP_PASS;
    }


    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
