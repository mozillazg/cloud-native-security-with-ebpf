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

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    pid_t tid;
    struct event_t event = {};
    char *filename;
    u32 SIGKILL = 9;

    tid = (pid_t)bpf_get_current_pid_tgid();
    // 获取进程 id
    event.pid = bpf_get_current_pid_tgid() >> 32;
    // 执行 execve 的进程名称
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    // 从 ctx->args[0] 中获取被执行的程序的名称
    filename = (char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), filename);

    long ret = bpf_send_signal(SIGKILL);
    if (ret != 0)
        return 0;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char _license[] SEC("license") = "GPL";
