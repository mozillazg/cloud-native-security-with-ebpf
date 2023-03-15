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

static bool is_suid_file(const struct file *file) {
    umode_t mode = BPF_CORE_READ(file, f_inode, i_mode);
    return S_ISREG(mode) && S_ISSUID(mode);
}

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(kprobe_security_bprm_check, struct linux_binprm *bprm) {
    struct event_t event = {};
    struct file *file = BPF_CORE_READ(bprm, file);

    // 判断是否是拥有 suid 权限的文件
    if (!is_suid_file(file))
        return 0;

    u32 uid = bpf_get_current_uid_gid();
    event.uid = uid;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    get_file_path(file, event.filename, sizeof(event.filename));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char _license[] SEC("license") = "GPL";
