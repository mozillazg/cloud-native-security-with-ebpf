#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "main.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event_t);
} tmp_storage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, u64);
    __type(value, unsigned int);
} fd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, u64);
    __type(value, long unsigned int);
} buffer_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    char passwd_path[TASK_COMM_LEN] = "/etc/passwd";
    char pathname[TASK_COMM_LEN];
    char *pathname_p = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_core_read_user_str(&pathname, TASK_COMM_LEN, pathname_p);
    if (!str_eq(pathname, passwd_path, TASK_COMM_LEN)) {
        return 0;
    }

    u64 tid = bpf_get_current_pid_tgid();
    unsigned int val = 0;
    bpf_map_update_elem(&fd_map, &tid, &val, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint_syscalls__sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    if (!bpf_map_lookup_elem(&fd_map, &tid)) {
        return 0;
    }

    unsigned int fd = (unsigned int)BPF_CORE_READ(ctx, ret);
    bpf_map_update_elem(&fd_map, &tid, &fd, BPF_ANY);

    return 0;
}


SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint_syscalls__sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    unsigned int *target_fd;
    target_fd = bpf_map_lookup_elem(&fd_map, &tid);
    if (!target_fd) {
        return 0;
    }

    unsigned int fd = (unsigned int)BPF_CORE_READ(ctx, args[0]);
    if (fd != *target_fd) {
        return 0;
    }
    long unsigned int buffer = (long unsigned int)BPF_CORE_READ(ctx, args[1]);
    bpf_map_update_elem(&buffer_map, &tid, &buffer, BPF_ANY);

    return 0;
}


SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint_syscalls__sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    int zero = 0;
    struct event_t *event;
    u64 tid = bpf_get_current_pid_tgid();

    long unsigned int *buffer_p = bpf_map_lookup_elem(&buffer_map, &tid);
    if (!buffer_p) {
        return 0;
    }
    long unsigned int buffer = *buffer_p;
    if (buffer <= 0) {
        return 0;
    }
    long int read_size = (long int)BPF_CORE_READ(ctx, ret);
    if (read_size <= 0) {
        return 0;
    }

    event = bpf_map_lookup_elem(&tmp_storage, &zero);
    if (!event) {
        return 0;
    }
    bpf_probe_read_user(&event->content, sizeof(event->content), (char *)buffer);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct event_t));

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint_syscalls__sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
    u64 tid = bpf_get_current_pid_tgid();

    bpf_map_delete_elem(&fd_map, &tid);
    bpf_map_delete_elem(&buffer_map, &tid);

    return 0;
}

char _license[] SEC("license") = "GPL";
