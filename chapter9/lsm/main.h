struct event_t {
    pid_t pid;
    int fmode;
    char comm[16];
    char filename[160];
};
