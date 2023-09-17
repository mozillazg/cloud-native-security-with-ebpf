#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16


SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_syscall(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 tid = bpf_get_current_pid_tgid();

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    u64 uid = bpf_get_current_uid_gid();
    u32 gid = bpf_get_current_uid_gid() >> 32;

    char cwd[256];
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    struct fs_struct *fs = task->fs;
    struct path path = BPF_CORE_READ(task, fs, pwd);
    struct qstr dname = BPF_CORE_READ(path.dentry, d_name);
    bpf_probe_read_kernel_str(&cwd, sizeof(cwd), dname.name);

    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    unsigned int pid_ns_inum = BPF_CORE_READ(nsproxy, pid_ns_for_children, ns.inum);
    unsigned int uts_ns_inum = BPF_CORE_READ(nsproxy, uts_ns, ns.inum);
    unsigned int ipc_ns_inum = BPF_CORE_READ(nsproxy, ipc_ns, ns.inum);
    unsigned int mnt_ns_inum = BPF_CORE_READ(nsproxy, mnt_ns, ns.inum);
    unsigned int net_ns_inum = BPF_CORE_READ(nsproxy, net_ns, ns.inum);
    unsigned int time_ns_inum = BPF_CORE_READ(nsproxy, time_ns, ns.inum);
    unsigned int cgroup_ns_inum = BPF_CORE_READ(nsproxy, cgroup_ns, ns.inum);

    unsigned int level = BPF_CORE_READ(nsproxy, pid_ns_for_children, level);
    u32 pid_ns_tid = BPF_CORE_READ(task, thread_pid, numbers[level].nr);
    u32 pid_ns_pid = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);



    bpf_printk("pid: %d, tid: %d, comm: %s", pid, tid, comm);
    bpf_printk("uid: %d, gid: %d, cwd: %s", uid, gid, cwd);
    bpf_printk("pid_ns_inum: %u, uts_ns_inum: %u, ipc_ns_inum: %u", pid_ns_inum, uts_ns_inum, ipc_ns_inum);
    bpf_printk("mnt_ns_inum: %u, net_ns_inum: %u, time_ns_inum: %u", mnt_ns_inum, net_ns_inum, time_ns_inum);
    bpf_printk("cgroup_ns_inum: %u, pid_ns_tid: %u, pid_ns_pid: %u", cgroup_ns_inum, pid_ns_tid, pid_ns_pid);


    unsigned int user_ns_inum = BPF_CORE_READ(task, mm, user_ns, ns.inum);
    // u32 owner = BPF_CORE_READ(task, mm, user_ns, owner.val);
    // u32 group = BPF_CORE_READ(task, mm, user_ns, group.val);

    bpf_printk("mm_user_ns_inum: %u", user_ns_inum);

    struct task_struct *parent_task = BPF_CORE_READ(task ,real_parent);
    u32 ppid = BPF_CORE_READ(parent_task, tgid);
    char ppid_comm[TASK_COMM_LEN];
    bpf_probe_read_kernel_str(&ppid_comm, sizeof(ppid_comm), BPF_CORE_READ(parent_task, comm));
    unsigned int parent_level = BPF_CORE_READ(parent_task, nsproxy, pid_ns_for_children, level);
    u32 pid_ns_ppid = BPF_CORE_READ(parent_task, group_leader, thread_pid, numbers[parent_level].nr);

    bpf_printk("ppid: %u, comm: %s, pid_ns_ppid: %u", ppid, ppid_comm, pid_ns_ppid);

    u32 sessionid = BPF_CORE_READ(task, sessionid);
    u64 boot_ts = bpf_ktime_get_boot_ns();
    u64 monotonic_ts = bpf_ktime_get_ns();
    bpf_printk("sessionid: %u, boot_ts: %u, monotonic_ts: %u", sessionid, boot_ts, monotonic_ts);


    return 0;
}

char _license[] SEC("license") = "GPL";
