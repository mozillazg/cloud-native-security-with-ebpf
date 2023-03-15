// include/uapi/linux/stat.h
#define S_IFMT  00170000
#define S_IFREG  0100000
#define S_ISUID  0004000

#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISSUID(m)	(((m) & S_ISUID) != 0)

struct event_t {
    u32 uid;
    pid_t pid;
    char comm[16];
    char filename[16];
};
