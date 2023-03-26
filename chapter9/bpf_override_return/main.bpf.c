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

static __always_inline bool str_eq(const char *a, const char *b, int len)
{
    for (int i = 0; i < len; i++) {
        if (a[i] != b[i])
            return false;
        if (a[i] == '\0')
            break;
    }
    return true;
}

static __always_inline int str_len(char *s, int max_len)
{
    for (int i = 0; i < max_len; i++) {
        if (s[i] == '\0')
            return i;
    }
    if (s[max_len - 1] != '\0')
        return max_len;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    pid_t tid;
    struct event_t event = {};
    char *filename;
    u64 err = -1;
    char target_comm[TASK_COMM_LEN] = "cat";

    tid = (pid_t)bpf_get_current_pid_tgid();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    // 获取文件打开模式
    event.fmode = (int)BPF_CORE_READ(ctx, args[3]);
    // 从 ctx->args[1] 中获取被打开的文件名称
    filename = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), filename);

    // 保存获取到的 event 信息
    bpf_map_update_elem(&entries, &tid, &event, BPF_NOEXIST);

    // 决策是否需要替换返回值 ...
    if (!str_eq(event.comm, target_comm, str_len(target_comm, TASK_COMM_LEN)))
        return 0;
    // 然后保存要替换的返回值
    bpf_map_update_elem(&override_tasks, &tid, &err, BPF_NOEXIST);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint_syscalls__sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    pid_t tid;
    struct event_t *event;

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

SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(kprobe_sys_openat_with_override)
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
