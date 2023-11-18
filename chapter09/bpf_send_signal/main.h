#define TASK_COMM_LEN 16
#define SIGKILL 9

struct event_t {
    pid_t pid;
    int fmode;
    char comm[TASK_COMM_LEN];
    char filename[16];
};
