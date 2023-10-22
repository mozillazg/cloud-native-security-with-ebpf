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

static void get_file_path(const struct file *file, char *buf, size_t size)
{
    struct qstr dname;
    dname = BPF_CORE_READ(file, f_path.dentry, d_name);
    bpf_probe_read_kernel(buf, size, dname.name);
}

static bool is_memory_file(const struct file *file) {
    unsigned int __i_nlink;
    __i_nlink = (unsigned int)BPF_CORE_READ(file, f_path.dentry, d_inode, __i_nlink);
    return __i_nlink <= 0;
}

SEC("lsm/bprm_creds_from_file")
int BPF_PROG(lsm_bprm_creds_from_file, struct linux_binprm *bprm, struct file *file, int ret) {
    struct event_t event = {};
    struct task_struct *task;

    // 判断是否是内存文件
    if (!is_memory_file(file))
        return ret;

    task = (struct task_struct*)bpf_get_current_task();
    event.ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    get_file_path(file, event.filename, sizeof(event.filename));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return ret;
}

char _license[] SEC("license") = "GPL";
