
struct event_t {
    u32 pid;
    u32 src_fd;
    u32 dst_fd;
    char comm[16];
    char dst_fd_filename[16];
};


struct fd_key_t {
    u32 pid;
    u32 fd;
};

struct fd_value_t {
    char filename[256];
};
