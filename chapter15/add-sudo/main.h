
#define TASK_COMM_LEN 16

struct event_t {
    u32 pid;
    u32 uid;
    u32 ret;
    char comm[TASK_COMM_LEN];
};

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

static __always_inline int str_len(char *s, int max_len)
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
