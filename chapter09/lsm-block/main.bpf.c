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

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file) {
    struct event_t event = {};
    char target_comm[TASK_COMM_LEN] = "cat";

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // 决策是否需要拦截当前事件 ...
    if (!str_eq(event.comm, target_comm, str_len(target_comm, TASK_COMM_LEN)))
        return 0;

    // 获取打开模式
    event.fmode = BPF_CORE_READ(file, f_mode);
    // 获取文件名称
    get_file_path(file, event.filename, sizeof(event.filename));

    // 将事件提交到 events 中供用户态程序消费
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    // 拦截
    return -1;
}

char _license[] SEC("license") = "GPL";
