#include "proto.h"
#include "checksum.h"
#include <string.h>
#include <stdlib.h>
#include "platform.h"

/* Header layout:
 * magic (4) | version (1) | type (1) | flags (1) | hdr_len (1) |
 * payload_len (4) | dcid (8) | scid (8) | ctrl_seq (4) | ctrl_ack (4) | checksum (4)
 */

size_t proto_header_size(void) {
    return 4 + 1 + 1 + 1 + 1 + 4 + 8 + 8 + 4 + 4 + 4;
}

static void write_u32(uint8_t *p, uint32_t v) { uint32_t n = htonl(v); memcpy(p, &n, 4); }
static void write_u64(uint8_t *p, uint64_t v) {
    uint32_t hi = htonl((uint32_t)(v >> 32));
    uint32_t lo = htonl((uint32_t)(v & 0xffffffffu));
    memcpy(p, &hi, 4);
    memcpy(p + 4, &lo, 4);
}

static uint32_t read_u32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return ntohl(v); }
static uint64_t read_u64(const uint8_t *p) {
    uint32_t hi, lo;
    memcpy(&hi, p, 4);
    memcpy(&lo, p + 4, 4);
    return ((uint64_t)ntohl(hi) << 32) | ntohl(lo);
}
//在发送方编码报文时
int proto_encode(const struct proto_packet *pkt, uint8_t *buf, size_t buf_cap, size_t *out_len) {
    const size_t hdr_len = proto_header_size();
    if (buf_cap < hdr_len + pkt->payload_len) return -1;
    //清零协议头，其中校验和所在字段也置零
    memset(buf, 0, hdr_len);
    //把自定义协议头按固定布局写进发送缓冲区 buf
    write_u32(buf, PROTO_MAGIC);
    buf[4] = PROTO_VERSION;
    buf[5] = (uint8_t)pkt->type;
    buf[6] = pkt->flags;
    buf[7] = (uint8_t)hdr_len;
    write_u32(buf + 8, pkt->payload_len);
    write_u64(buf + 12, pkt->dcid);
    write_u64(buf + 20, pkt->scid);
    write_u32(buf + 28, pkt->ctrl_seq);
    write_u32(buf + 32, pkt->ctrl_ack);
    /* checksum placeholder at buf+36, kept zero initially */
    // 把整个报文包括协议头和要发送的负载数据作为校验对象。
    if (pkt->payload_len && pkt->payload) {
        memcpy(buf + hdr_len, pkt->payload, pkt->payload_len);
    }
    //校验和的覆盖范围包括协议头和数据负载，也就是说，只要报文中任意一个比特发生错误，校验和就会不一致。
    //对协议头和数据负载整体计算 16 位校验和
    uint16_t csum = checksum16(buf, hdr_len + pkt->payload_len);
    //把结果写进协议头校验和字段。
    write_u32(buf + 36, (uint32_t)csum);
    //校验和本身是 16 位的，为了对齐协议头，我在协议中为其预留了 32 位空间，实际只使用低 16 位。
    if (out_len) *out_len = hdr_len + pkt->payload_len;
    return 0;
}

int proto_decode(const uint8_t *buf, size_t len, struct proto_packet *pkt) {
    const size_t hdr_len = proto_header_size();
    if (len < hdr_len) return -1;
    if (read_u32(buf) != PROTO_MAGIC) return -1;
    if (buf[4] != PROTO_VERSION) return -1;
    if (buf[7] != hdr_len) return -1;
    uint32_t payload_len = read_u32(buf + 8);
    if (hdr_len + payload_len != len) return -1;
    //去除报文中携带的校验和
    uint32_t stored_checksum = read_u32(buf + 36);
    uint8_t *tmp = (uint8_t *)malloc(len);
    if (!tmp) return -1;
    memcpy(tmp, buf, len);
    memset(tmp + 36, 0, 4);
    //在重新计算校验和时，我会先把报文中的校验和字段清零，然后对整个报文重新计算，这样可以保证计算规则和发送端完全一致。
    uint16_t calc = checksum16(tmp, len);
    free(tmp);
    //不一致就丢弃
    if ((uint16_t)stored_checksum != calc) return -1;

    pkt->type = (enum proto_type)buf[5];
    pkt->flags = buf[6];
    pkt->dcid = read_u64(buf + 12);
    pkt->scid = read_u64(buf + 20);
    pkt->ctrl_seq = read_u32(buf + 28);
    pkt->ctrl_ack = read_u32(buf + 32);
    pkt->payload_len = payload_len;
    pkt->payload = payload_len ? buf + hdr_len : NULL;
    return 0;
}
