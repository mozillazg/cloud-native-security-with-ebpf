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
} execs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, u64);
} override_tasks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    pid_t tid;
    struct event_t event = {};
    struct task_struct *task;
    char *filename;
    u64 err = -1;

    tid = (pid_t)bpf_get_current_pid_tgid();
    task = (struct task_struct*)bpf_get_current_task();
    // 执行操作的进程 id
    event.ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
    // 获取进程 id
    event.pid = bpf_get_current_pid_tgid() >> 32;
    // 执行 execve 的进程名称
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    // 从 ctx->args[0] 中获取被执行的程序的名称
    filename = (char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), filename);

    // 保存获取到的 event 信息
    bpf_map_update_elem(&execs, &tid, &event, BPF_NOEXIST);

    // 决策是否需要替换返回值 ...
    // 然后保存要替换的返回值
    bpf_map_update_elem(&override_tasks, &tid, &err, BPF_NOEXIST);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint_syscalls__sys_exit_execve(struct trace_event_raw_sys_exit *ctx) {
    pid_t tid;
    struct event_t *event;

    // 获取 execs 中保存的 event 信息
    tid = (pid_t)bpf_get_current_pid_tgid();
    event = bpf_map_lookup_elem(&execs, &tid);
    if (!event)
        return 0;

    // 保存执行结果
    event->ret = (int)BPF_CORE_READ(ctx, ret);
    // 将事件提交到 events 中供用户态程序消费
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    // 删除保存的 event 信息
    bpf_map_delete_elem(&execs, &tid);
    return 0;
}

SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE(kprobe_sys_execve_with_override)
{
    pid_t tid;
    u64 *err;

    // 查找是否需要替换返回值
    tid = (pid_t)bpf_get_current_pid_tgid();
    err = bpf_map_lookup_elem(&override_tasks, &tid);
    if (!err)
        return 0;

    // 替换返回值
    bpf_override_return(ctx, *err);
    bpf_map_delete_elem(&override_tasks, &tid);
    return 0;
}

char _license[] SEC("license") = "GPL";
