#pragma once

#include <stdint.h>
#include <stddef.h>

#define PROTO_MAGIC 0x43304e4eU /* "C0NN" */
#define PROTO_VERSION 1

/* Data plane constants */
#define PROTO_WIN_SIZE 48
#define PROTO_MAX_SEG_SIZE 1024
#define PROTO_MAX_SACK 8

enum proto_type {
    PROTO_SYN = 1,
    PROTO_SYN_ACK = 2,
    PROTO_ACK = 3,
    PROTO_FIN = 4,
    PROTO_RST = 5,
    PROTO_DATA = 6
};

struct proto_packet {
    enum proto_type type;
    uint8_t flags;
    uint64_t dcid;
    uint64_t scid;
    uint32_t ctrl_seq;
    uint32_t ctrl_ack;
    const uint8_t *payload;
    uint32_t payload_len;
};

/* Per-DATA segment header (network byte order on wire) */
struct proto_data_hdr {
    uint32_t seg_seq;
    uint16_t seg_len;
    uint16_t flags;
};

struct proto_sack_block {
    uint32_t start; /* inclusive */
    uint32_t end;   /* exclusive */
};

/* ACK payload layout:
 * uint32_t ack_seq;
 * uint16_t sack_count;
 * uint16_t reserved;
 * sack_count * proto_sack_block
 */

/* Encodes packet into buf. Returns 0 on success, -1 on overflow. */
int proto_encode(const struct proto_packet *pkt, uint8_t *buf, size_t buf_cap, size_t *out_len);

/* Decodes buffer into pkt. Returns 0 on success, -1 on malformed/short. */
int proto_decode(const uint8_t *buf, size_t len, struct proto_packet *pkt);

/* Fixed header size (bytes) for preallocation. */
size_t proto_header_size(void);
