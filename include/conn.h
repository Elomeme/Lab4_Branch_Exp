#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "platform.h"
#include "proto.h"
#include "timer.h"

enum conn_state {
    CONN_CLOSED = 0,
    CONN_LISTEN,
    CONN_SYN_SENT,
    CONN_SYN_RCVD,
    CONN_ESTABLISHED,
    CONN_FIN_WAIT_1,
    CONN_FIN_WAIT_2,
    CONN_CLOSE_WAIT,
    CONN_LAST_ACK,
    CONN_TIME_WAIT
};

struct pending_ctrl {
    enum proto_type type;
    uint32_t ctrl_seq;
    uint32_t ctrl_ack;
    uint32_t payload_len;
    uint8_t payload[128]; /* small control payload buffer */
};
//保存一条逻辑链接的全部状态
struct conn {
    uint64_t my_cid;
    uint64_t peer_cid;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;
    enum conn_state state;
    uint32_t ctrl_tx_next;
    uint32_t last_acked_ctrl;
    struct pending_ctrl pending;
    bool has_pending;
    struct timer ctrl_timer;
    uint32_t max_retries;
    uint64_t rto_max_ms;
    uint64_t time_wait_until_ms;
    /* ===== Data plane ===== */
    //发送和接收序列号
    //最早未确认段号（窗口左边界）
    uint32_t snd_base;
    //snd_next：下一个要分配/入队的段号
    uint32_t snd_next;
    //snd_win：固定窗口大小（流量控制窗口）
    uint32_t snd_win;
    uint32_t snd_highest; /* highest seq ever sent */
    uint32_t rcv_base;//按序已经收到的最大前缀的“下一个期望段号”（也就是累计 ACK 的值）
    uint32_t rcv_win;//固定接收窗口大小（作业要求固定窗口）
    uint64_t data_rto_base_ms;
    uint64_t data_rto_ms;
    uint32_t data_retx_count;
    uint32_t ctrl_retx_count;
    struct {
        bool in_use;
        bool sent;
        bool acked;
        uint64_t last_send_ts;
        uint16_t len;
        uint8_t data[PROTO_MAX_SEG_SIZE];
    } send_buf[PROTO_WIN_SIZE];
    //接收缓冲区，序号会无限增长，内存不能无限增长，所以用环形缓冲区实现
    struct {
        bool received;
        uint16_t len;
        uint8_t data[PROTO_MAX_SEG_SIZE];
    } recv_buf[PROTO_WIN_SIZE];
    //乱序缓存（环形槽），保存“窗口内收到但还不能按序交付”的段
    uint32_t deliver_seq;    /* next seq to deliver to app */
    uint32_t app_recv_ready; /* count of contiguous ready segments */
    /* Congestion control */
    //cwnd：拥塞窗口（Reno，单位段）
    uint32_t cwnd;       /* in segments */
    uint32_t ssthresh;   /* in segments */
    uint32_t dup_acks;
    uint32_t ca_count;   /* counter for congestion avoidance */
    bool in_fast_recovery;
    uint32_t recover_seq;
    uint32_t last_ack_seq;
};

#define CONN_TABLE_MAX 128

struct conn_table {
    struct conn *items[CONN_TABLE_MAX];
    size_t count;
    uint32_t default_win;
};

void conn_table_init(struct conn_table *ct);
/* Set default fixed window (segments) for new conns; clamped to [1, PROTO_WIN_SIZE]. */
void conn_table_set_default_win(struct conn_table *ct, uint32_t win);
struct conn *conn_lookup(struct conn_table *ct, uint64_t my_cid);
struct conn *conn_add(struct conn_table *ct, uint64_t my_cid);
void conn_remove(struct conn_table *ct, uint64_t my_cid);

/* Client API */
struct conn *conn_client_connect(struct conn_table *ct, socket_t sockfd, const struct sockaddr_storage *peer, socklen_t peerlen);
void conn_client_close(struct conn *c, socket_t sockfd);

/* Server-side helper for LISTEN -> SYN_RCVD */
struct conn *conn_server_accept_syn(struct conn_table *ct, socket_t sockfd, const struct proto_packet *pkt, const struct sockaddr_storage *peer, socklen_t peerlen);

/* Process inbound packet (post-decode). */
void conn_handle_packet(struct conn_table *ct, struct conn *c, socket_t sockfd, const struct proto_packet *pkt);

/* Tick timers: retransmissions + time_wait cleanup. */
void conn_tick_all(struct conn_table *ct, socket_t sockfd, uint64_t now_ms);

/* Send best-effort data when established. */
int conn_send_data(struct conn *c, socket_t sockfd, const uint8_t *data, uint32_t len);
void conn_flush_data(struct conn *c, socket_t sockfd);
void conn_flush_all(struct conn_table *ct, socket_t sockfd);

/* Application receive: returns length copied into buf (<=cap), 0 if none. */
int conn_recv_next(struct conn *c, uint8_t *buf, uint32_t cap);

/* Utility to log a human-readable address. */
const char *conn_format_addr(const struct sockaddr_storage *addr, char *buf, size_t buflen);
