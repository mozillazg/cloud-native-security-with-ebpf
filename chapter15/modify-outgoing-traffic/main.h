#define ETH_P_IP    0x0800      /* Internet Protocol packet */
#define ETH_HLEN    14         /* Total octets in header.   */

#define TC_ACT_UNSPEC         (-1)
#define TC_ACT_OK               0
#define TC_ACT_SHOT             2
#define TC_ACT_STOLEN           4
#define TC_ACT_REDIRECT         7


struct event_t {
    u32 is_ingress;
    u32 src_addr;
    u32 dst_addr;
    u8 type;
    u8 code;
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