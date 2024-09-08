#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/ // ipv4
#define ETH_HLEN 14 /* Total octets in header.	 */
#define TASK_COMM_LEN 16
#define TC_ACT_UNSPEC (-1)


struct sock_key {
    u32 saddr;
    u16 sport;
    u32 daddr;
    u16 dport;
};

struct sock_value {
    u32 net_ns_inum;
    u32 pid_ns_inum;
    u64 host_tid;
    u32 host_pid;
    u64 pid_ns_tid;
    u32 pid_ns_pid;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct sock *);
} tid_socks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct sock_key);
    __type(value, struct sock_value);
} socks SEC(".maps");


SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(enter_tcp_connect, struct sock *sk) {
    u64 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tid_socks, &tid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(exit_tcp_connect, int ret) {
    struct sock_key key = {0};
    struct sock_value value = {0};
    struct sock **skp;
    struct sock *sk;

    u64 tid = bpf_get_current_pid_tgid();
    skp = bpf_map_lookup_elem(&tid_socks, &tid);
    if (!skp) {
        return 0;
    }
    if (ret) {
        goto end;
    }
    sk = *skp;

    key.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    value.host_tid = tid;
    value.host_pid = tid >> 32;

    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    value.pid_ns_inum = BPF_CORE_READ(nsproxy, pid_ns_for_children, ns.inum);
    value.net_ns_inum = BPF_CORE_READ(nsproxy, net_ns, ns.inum);

    unsigned int level = BPF_CORE_READ(nsproxy, pid_ns_for_children, level);
    value.pid_ns_tid = BPF_CORE_READ(task, thread_pid, numbers[level].nr);
    value.pid_ns_pid = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);
    bpf_get_current_comm(&value.comm, sizeof(value.comm));

    bpf_map_update_elem(&socks, &key, &value, BPF_ANY);

end:
    bpf_map_delete_elem(&tid_socks, &tid);
    return 0;
}

SEC("kprobe/inet_release")
int BPF_KPROBE(free_connect, struct socket *socket)
{
    struct sock *sk;
    sk = BPF_CORE_READ(socket, sk);
    if (!sk) {
        return 0;
    }

    struct sock_key key = {0};
    key.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    bpf_map_delete_elem(&socks, &key);
    return 0;
}

SEC("iter/task_file")
int iter_task_file(struct bpf_iter__task_file *ctx) {
    struct task_struct *task = ctx->task;
    struct file *file = ctx->file;
    struct socket *socket;
    struct sock *sk;
    struct sock_key key = {0};
    struct sock_value value = {0};

    if (!task || !file) {
        return 0;
    }
    socket = bpf_sock_from_file(file);
    if (!socket) {
        return 0;
    }

    sk = BPF_CORE_READ(socket, sk);
    key.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    value.host_tid = BPF_CORE_READ(task, pid);
    value.host_pid = BPF_CORE_READ(task, tgid);

    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    value.pid_ns_inum = BPF_CORE_READ(nsproxy, pid_ns_for_children, ns.inum);
    value.net_ns_inum = BPF_CORE_READ(nsproxy, net_ns, ns.inum);

    unsigned int level = BPF_CORE_READ(nsproxy, pid_ns_for_children, level);
    value.pid_ns_tid = BPF_CORE_READ(task, thread_pid, numbers[level].nr);
    value.pid_ns_pid = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);
    bpf_probe_read_kernel_str(&value.comm, sizeof(value.comm), BPF_CORE_READ(task, comm));

    bpf_map_update_elem(&socks, &key, &value, BPF_NOEXIST);

    bpf_printk("iter task file");
    // BPF_SEQ_PRINTF(ctx->meta->seq, "%d", value.host_tid);
    return 0;
}



SEC("tc")
int on_egress(struct __sk_buff *skb) {
    struct sock_key key = {0};
    struct sock_value *value;

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    if ((data + ETH_HLEN + sizeof(struct iphdr)) > data_end)
        return TC_ACT_UNSPEC;
    struct iphdr *ip_hdr = data + ETH_HLEN;
    if (ip_hdr->protocol != IPPROTO_TCP)
        return TC_ACT_UNSPEC;
    struct tcphdr *tcp_hdr = (void *)ip_hdr + sizeof(struct iphdr);
    if ((void *)tcp_hdr + sizeof(struct tcphdr) > data_end) {
        return TC_ACT_UNSPEC;
    }

    key.saddr = ip_hdr->saddr;
    key.sport = bpf_ntohs(tcp_hdr->source);
    key.daddr = ip_hdr->daddr;
    key.dport = tcp_hdr->dest;

    value = bpf_map_lookup_elem(&socks, &key);
    if (!value) {
        return TC_ACT_UNSPEC;
    }
    u32 daddr = ip_hdr->daddr;
    u16 dport = bpf_ntohs(tcp_hdr->dest);

    bpf_printk("%d %u %u", value->host_pid, value->pid_ns_inum, value->net_ns_inum);
    bpf_printk("%s %pI4:%d", value->comm, &key.saddr, key.sport);
    bpf_printk("%s               -> %pI4:%d", value->comm, &daddr, dport);

    return TC_ACT_UNSPEC;
}


char _license[] SEC("license") = "GPL";
