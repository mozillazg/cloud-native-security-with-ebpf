#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "main.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 20480);
    __type(key, struct fd_key_t);
    __type(value, struct fd_value_t);
} fd_map SEC(".maps");

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

SEC("kprobe/fd_install")
int BPF_KPROBE(kprobe__fd_install, unsigned int fd, struct file *file) {
    struct fd_key_t key = { 0 };
    struct fd_value_t value = { 0 };
    key.fd = fd;
    key.pid = bpf_get_current_pid_tgid() >> 32;

    get_file_path(file, value.filename, sizeof(value.filename));

    char tcp_filename[4] = "TCP";
    if (!(fd == 0 || fd == 1 || fd == 2 || str_eq(value.filename, tcp_filename, 4))) {
        return 0;
    }

    bpf_map_update_elem(&fd_map, &key, &value, BPF_ANY);

    return 0;
}

static void handle_dup_event(struct trace_event_raw_sys_enter *ctx) {
    struct fd_key_t key = { 0 };
    struct fd_value_t *value;
    struct event_t event = { 0 };

    key.pid = bpf_get_current_pid_tgid() >> 32;
    key.fd = (u32)BPF_CORE_READ(ctx, args[0]);
    value = bpf_map_lookup_elem(&fd_map, &key);
    if (!value) {
        return;
    }

    char tcp_filename[4] = "TCP";
    if (!str_eq(value->filename, tcp_filename, 4)) {
        return;
    }

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.src_fd = (u32)BPF_CORE_READ(ctx, args[1]);
    event.dst_fd = key.fd;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_kernel_str(&event.dst_fd_filename, sizeof(event.dst_fd_filename), &value->filename);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int tracepoint_syscalls__sys_enter_dup2(struct trace_event_raw_sys_enter *ctx) {
    handle_dup_event(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int tracepoint_syscalls__sys_enter_dup3(struct trace_event_raw_sys_enter *ctx) {
    handle_dup_event(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint_syscalls__sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
    struct fd_key_t key = { 0 };

    key.pid = bpf_get_current_pid_tgid() >> 32;
    key.fd = (u32)BPF_CORE_READ(ctx, args[0]);

    bpf_map_delete_elem(&fd_map, &key);

    return 0;
}

char _license[] SEC("license") = "GPL";
