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
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("ksyscall/execve")
int BPF_KSYSCALL(ksyscall_execve, const char *filename) {
    pid_t tid;
    struct task_struct *task;
    struct event_t event = {};

    tid = (pid_t)bpf_get_current_pid_tgid();
    task = (struct task_struct*)bpf_get_current_task();
    // 执行操作的进程 id
    event.ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
    // 获取进程 id
    event.pid = bpf_get_current_pid_tgid() >> 32;
    // 执行 execve 的进程名称
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    // 获取被执行的程序的名称
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), (const char*)filename);

    // 保存获取到的 event 信息
    bpf_map_update_elem(&execs, &tid, &event, BPF_NOEXIST);
    return 0;
}

SEC("kretsyscall/execve")
int BPF_KRETPROBE(kretsyscall_execve, long ret) {
    pid_t tid;
    struct event_t *event;

    // 获取 ksyscall_execve 中保存的 event 信息
    tid = (pid_t)bpf_get_current_pid_tgid();
    event = bpf_map_lookup_elem(&execs, &tid);
    if (!event)
        return 0;

    // 保存执行结果
    event->ret = ret;
    // 将事件提交到 events 中供用户态程序消费
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    // 删除保存的 event 信息
    bpf_map_delete_elem(&execs, &tid);
    return 0;
}

char _license[] SEC("license") = "GPL";
