
#define TASK_COMM_LEN 16
#define MAX_NAME 8
#define MAX_PIPE_NUM 10

struct event_t {
    u32 pid;
    u32 ret;
    char hidden_pid[MAX_NAME];
    char comm[TASK_COMM_LEN];
};


struct pipe_pair_t {
    int read_fd;
    int write_fd;
};


struct pipe_point_t {
    u32 pid;
    int *fildes;
};

struct pipe_fd_key_t {
    u32 pid;
    int fd;
};

struct pipe_fd_val_t {
    int read_fd;
    int write_fd;
};

struct fork_t {
    u32 ppid;
    u32 pid;
};

struct dup_fd_key_t {
    u32 pid;
    int src_fd;
};

struct dup_fd_val_t {
    int target_fd;
};

struct read_buf_key_t {
    u32 pid;
    void *buf;
};

struct read_buf_t {
    long unsigned int buf_p;
    int read_count;
};

struct write_buf_t {
    int write_count;
};

static __always_inline void get_file_path(const struct file *file, char *buf, size_t size)
{
    struct qstr dname;
    dname = BPF_CORE_READ(file, f_path.dentry, d_name);
    bpf_probe_read_kernel(buf, size, dname.name);
}

static __always_inline bool str_eq(const char *a, const char *b, int len)
{
#pragma unroll
    for (int i = 0; i < len; i++) {
        if (a[i] != b[i])
            return false;
        if (a[i] == '\0')
            break;
    }
    return true;
}

static __always_inline int str_len(const char *s, int max_len)
{
#pragma unroll
    for (int i = 0; i < max_len; i++) {
        if (s[i] == '\0')
            return i;
    }
    if (s[max_len - 1] != '\0')
        return max_len;
    return 0;
}
