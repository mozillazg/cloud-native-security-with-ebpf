#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "main.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static inline bool str_eq(const char *a, const char *b, int len)
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
    struct event_t event = {};
    char *filename;
    char target_comm[TASK_COMM_LEN] = "cat";

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // 决策是否需要拦截当前事件 ...
    if (!str_eq(event.comm, target_comm, str_len(target_comm, TASK_COMM_LEN)))
        return 0;
    // 拦截
    if (bpf_send_signal(SIGKILL) != 0)
        return 0;

    // 获取文件打开模式
    event.fmode = (int)BPF_CORE_READ(ctx, args[3]);
    // 从 ctx->args[1] 中获取被打开的文件名称
    filename = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), filename);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char _license[] SEC("license") = "GPL";
