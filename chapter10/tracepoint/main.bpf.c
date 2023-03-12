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

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    pid_t tid;
    struct event_t event = {};
    char *filename;

    tid = (pid_t)bpf_get_current_pid_tgid();
    // 获取进程 id
    event.pid = bpf_get_current_pid_tgid() >> 32;
    // 执行 openat 的进程名称
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    // 获取文件打开模式
    event.fmode = (int)BPF_CORE_READ(ctx, args[3]);
    // 从 ctx->args[1] 中获取被打开的文件名称
    filename = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), filename);

    // 保存获取到的 event 信息
    bpf_map_update_elem(&entries, &tid, &event, BPF_NOEXIST);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint_syscalls__sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    pid_t tid;
    struct event_t *event;

    // 获取 tracepoint_syscalls__sys_enter_openat 中保存的 event 信息
    tid = (pid_t)bpf_get_current_pid_tgid();
    event = bpf_map_lookup_elem(&entries, &tid);
    if (!event)
        return 0;

    // 保存执行结果
    event->ret = (int)BPF_CORE_READ(ctx, ret);
    // 将事件提交到 events 中供用户态程序消费
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    // 删除保存的 event 信息
    bpf_map_delete_elem(&entries, &tid);
    return 0;
}

char _license[] SEC("license") = "GPL";
