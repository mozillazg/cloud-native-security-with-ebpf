#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "main.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, struct event_t);
} entries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static void get_file_path(const struct file *file, char *buf, size_t size)
{
    struct qstr dname;

    dname = BPF_CORE_READ(file, f_path.dentry, d_name);
    bpf_probe_read_kernel(buf, size, dname.name);
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file) {
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    // 获取打开模式
    event.fmode = BPF_CORE_READ(file, f_mode);
    // 获取文件名称
    get_file_path(file, event.filename, sizeof(event.filename));

    // 将事件提交到 events 中供用户态程序消费
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char _license[] SEC("license") = "GPL";
