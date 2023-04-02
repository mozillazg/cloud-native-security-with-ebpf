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
