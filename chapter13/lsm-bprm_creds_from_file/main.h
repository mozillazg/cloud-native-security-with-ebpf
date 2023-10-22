
struct event_t {
    pid_t ppid;
    pid_t pid;
    char comm[16];
    char filename[160];
};
