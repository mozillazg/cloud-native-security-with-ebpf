struct event_t {
    pid_t pid;
    int fmode;
    int ret;
    char comm[16];
    char filename[160];
};
