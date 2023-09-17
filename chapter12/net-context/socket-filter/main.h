#define ETH_P_IP    0x0800      /* Internet Protocol packet */
#define ETH_HLEN    14         /* Total octets in header.   */

struct event_t {
    u32 src_addr;
    u32 dst_addr;
    u8 type;
    u8 code;
};
