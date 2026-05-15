#include "conn.h"
#include "proto.h"
#include "util.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>

static void send_control(struct conn *c, socket_t sockfd, enum proto_type type, uint32_t ctrl_ack, const uint8_t *payload, uint32_t payload_len, uint64_t dcid_override);
static void send_ack_only(struct conn *c, socket_t sockfd, uint32_t ctrl_ack);
static void retransmit(struct conn *c, socket_t sockfd);
static void send_data_segment(struct conn *c, socket_t sockfd, uint32_t seq);
static void send_ack_for_rcv(struct conn *c, socket_t sockfd);
static void handle_data_pkt(struct conn *c, socket_t sockfd, const struct proto_packet *pkt);
static void handle_ack_pkt(struct conn *c, socket_t sockfd, const struct proto_packet *pkt);
static void enter_fast_recovery(struct conn *c, socket_t sockfd);

void conn_table_init(struct conn_table *ct) {
    ct->count = 0;
    memset(ct->items, 0, sizeof(ct->items));
    ct->default_win = PROTO_WIN_SIZE;
}

void conn_table_set_default_win(struct conn_table *ct, uint32_t win) {
    if (!ct) return;
    if (win < 1) win = 1;
    if (win > PROTO_WIN_SIZE) win = PROTO_WIN_SIZE;
    ct->default_win = win;
}

struct conn *conn_lookup(struct conn_table *ct, uint64_t my_cid) {
    for (size_t i = 0; i < ct->count; ++i) {
        if (ct->items[i] && ct->items[i]->my_cid == my_cid) return ct->items[i];
    }
    return NULL;
}

struct conn *conn_add(struct conn_table *ct, uint64_t my_cid) {
    if (ct->count >= CONN_TABLE_MAX) return NULL;
    struct conn *c = (struct conn *)calloc(1, sizeof(struct conn));
    if (!c) return NULL;
    c->my_cid = my_cid;
    c->peer_cid = 0;
    c->state = CONN_CLOSED;
    c->ctrl_tx_next = 1;
    c->last_acked_ctrl = 0;
    c->max_retries = 5;
    c->rto_max_ms = 4000;
    c->snd_base = 1;
    c->snd_next = 1;
    c->snd_win = (ct && ct->default_win) ? ct->default_win : PROTO_WIN_SIZE;
    c->snd_highest = 0;
    c->rcv_base = 1;
    c->rcv_win = c->snd_win;
    c->data_rto_base_ms = 800;
    c->data_rto_ms = c->data_rto_base_ms;
    c->deliver_seq = 1;
    c->app_recv_ready = 0;
    c->cwnd = 10;
    c->ssthresh = PROTO_WIN_SIZE;
    c->dup_acks = 0;
    c->ca_count = 0;
    c->in_fast_recovery = false;
    c->recover_seq = 0;
    c->last_ack_seq = 0;
    ct->items[ct->count++] = c;
    return c;
}

void conn_remove(struct conn_table *ct, uint64_t my_cid) {
    for (size_t i = 0; i < ct->count; ++i) {
        if (ct->items[i] && ct->items[i]->my_cid == my_cid) {
            free(ct->items[i]);
            ct->items[i] = ct->items[ct->count - 1];
            ct->items[ct->count - 1] = NULL;
            ct->count--;
            return;
        }
    }
}

static void conn_set_peer(struct conn *c, const struct sockaddr_storage *peer, socklen_t peerlen) {
    memcpy(&c->peer_addr, peer, peerlen);
    c->peer_addrlen = peerlen;
}

struct conn *conn_client_connect(struct conn_table *ct, socket_t sockfd, const struct sockaddr_storage *peer, socklen_t peerlen) {
    //生成cid，连接标识
    uint64_t my_cid = util_random64();
    //新建连接
    struct conn *c = conn_add(ct, my_cid);
    if (!c) return NULL;
    //保存对端地址，也就是记住这条连接“应该往哪一个 IP:端口发包
    conn_set_peer(c, peer, peerlen);
    //改变连接状态
    c->state = CONN_SYN_SENT;
    //发送SYN
    send_control(c, sockfd, PROTO_SYN, 0, NULL, 0, 0);//304
    LOG_INFO("client: SYN sent cid=%llu", (unsigned long long)c->my_cid);
    return c;
}

void conn_client_close(struct conn *c, socket_t sockfd) {
    if (!c || c->state != CONN_ESTABLISHED) return;
    c->state = CONN_FIN_WAIT_1;
    send_control(c, sockfd, PROTO_FIN, c->last_acked_ctrl, NULL, 0, 0);
    LOG_INFO("client: FIN sent");
}

struct conn *conn_server_accept_syn(struct conn_table *ct, socket_t sockfd, const struct proto_packet *pkt, const struct sockaddr_storage *peer, socklen_t peerlen) {
    //服务器端接受SYN请求
    /* Reuse existing half-open if duplicate SYN */
  //如果是重复 SYN，重传 SYN_ACK
    for (size_t i = 0; i < ct->count; ++i) {
        struct conn *c = ct->items[i];
        if (c && c->state == CONN_SYN_RCVD && c->peer_cid == pkt->scid && c->peer_addrlen == peerlen &&
            memcmp(&c->peer_addr, peer, peerlen) == 0) {
            retransmit(c, sockfd);
            return c;
        }
    }
    //否则生成 server 的 CID
    uint64_t my_cid = util_random64();
    struct conn *c = conn_add(ct, my_cid);
    if (!c) return NULL;
    conn_set_peer(c, peer, peerlen);
    //保存 peer 地址与 peer CID：
    c->peer_cid = pkt->scid;
    c->state = CONN_SYN_RCVD;
    //发送SYN_ACK.客户端handle_syn_ack
    send_control(c, sockfd, PROTO_SYN_ACK, pkt->ctrl_seq, NULL, 0, c->peer_cid);
    LOG_INFO("server: SYN_ACK sent my_cid=%llu peer_cid=%llu", (unsigned long long)c->my_cid, (unsigned long long)c->peer_cid);
    return c;
}
//处理收到的SYN_ACK包
static void handle_syn_ack(struct conn *c, socket_t sockfd, const struct proto_packet *pkt) {
    if (c->state == CONN_SYN_SENT) {
        c->peer_cid = pkt->scid;
        //建立连接
        c->state = CONN_ESTABLISHED;
        send_ack_only(c, sockfd, pkt->ctrl_seq);
        c->has_pending = false;
        //停止重传定时器
        timer_stop(&c->ctrl_timer);
        LOG_INFO("client: established (recv SYN_ACK seq=%u)", pkt->ctrl_seq);
    } else {
        send_ack_only(c, sockfd, pkt->ctrl_seq);
    }
}
//处理收到的FIN包
static void handle_fin(struct conn *c, socket_t sockfd, const struct proto_packet *pkt) {
    send_ack_only(c, sockfd, pkt->ctrl_seq);
    LOG_INFO("recv FIN cid=%llu seq=%u -> ack", (unsigned long long)c->my_cid, pkt->ctrl_seq);
    uint64_t now = util_now_ms();
    if (c->state == CONN_ESTABLISHED) {
        c->state = CONN_LAST_ACK;
        send_control(c, sockfd, PROTO_FIN, c->last_acked_ctrl, NULL, 0, 0);
    } else if (c->state == CONN_FIN_WAIT_1) {
        c->state = CONN_TIME_WAIT;
        c->time_wait_until_ms = now + 2000;
    } else if (c->state == CONN_FIN_WAIT_2) {
        c->state = CONN_TIME_WAIT;
        c->time_wait_until_ms = now + 2000;
    } else if (c->state == CONN_TIME_WAIT) {
        c->time_wait_until_ms = now + 2000;
    }
}
//处理收到的数据包
void conn_handle_packet(struct conn_table *ct, struct conn *c, socket_t sockfd, const struct proto_packet *pkt) {
    (void)ct;
    if (!c) return;
    if (pkt->ctrl_ack && pkt->ctrl_ack > c->last_acked_ctrl) c->last_acked_ctrl = pkt->ctrl_ack;
    bool acked_pending = c->has_pending && pkt->ctrl_ack >= c->pending.ctrl_seq;
    if (acked_pending) {
        if (c->pending.type == PROTO_SYN_ACK && c->state == CONN_SYN_RCVD) {
            c->state = CONN_ESTABLISHED;
            LOG_INFO("server: established");
        } else if (c->pending.type == PROTO_FIN && c->state == CONN_FIN_WAIT_1) {
            c->state = CONN_FIN_WAIT_2;
            LOG_INFO("fin acknowledged -> FIN_WAIT_2");
        } else if (c->pending.type == PROTO_FIN && c->state == CONN_LAST_ACK) {
            c->state = CONN_CLOSED;
            LOG_INFO("last ack received -> closed");
        }
        c->has_pending = false;
        timer_stop(&c->ctrl_timer);
    }

    switch (pkt->type) {
        case PROTO_SYN_ACK:
            handle_syn_ack(c, sockfd, pkt);
            break;
        case PROTO_ACK:
            handle_ack_pkt(c, sockfd, pkt);
            break;
        case PROTO_FIN:
            handle_fin(c, sockfd, pkt);
            break;
        case PROTO_DATA:
            handle_data_pkt(c, sockfd, pkt);
            break;
        case PROTO_RST:
            c->state = CONN_CLOSED;
            break;
        default:
            break;
    }
}
//处理所有连接的定时器，“统一定时器 + 拥塞反应 + 连接生命周期管理中枢”
void conn_tick_all(struct conn_table *ct, socket_t sockfd, uint64_t now_ms) {
    for (size_t i = 0; i < ct->count;) {
        struct conn *c = ct->items[i];
        if (!c) { ++i; continue; }
        bool congestion_handled = false;
        //连接关闭
        if (c->state == CONN_CLOSED) {
            conn_remove(ct, c->my_cid);
            continue;
        }
        //控制包超时
        if (c->has_pending && timer_expired(&c->ctrl_timer, now_ms)) {
            //若重试次数超过 max_retries → 认为连接失败，清理连接
            if (c->ctrl_timer.retries >= c->max_retries) {
                LOG_WARN("conn %llu retries exceeded, closing", (unsigned long long)c->my_cid);
                conn_remove(ct, c->my_cid);
                continue;
            }
            retransmit(c, sockfd);
            continue;
        }
        //TIME_WAIT到期，主动关闭方在 TIME_WAIT 等待 2MSL 后释放连接。
        if (c->state == CONN_TIME_WAIT && now_ms >= c->time_wait_until_ms) {
            LOG_INFO("conn %llu leaving TIME_WAIT", (unsigned long long)c->my_cid);
            conn_remove(ct, c->my_cid);
            continue;
        }
        
        //(数据 RTO 超时) 拥塞反应 + 重传，一次 RTO 超时代表一次拥塞事件
        //窗口里只要 snd_base （最早未确认段）这段没确认，就以它的发送时间作为 RTO 判断依据；它超时就重传它，并执行一次拥塞反应。

        /* Data retransmission timer: only track the oldest unacked segment */
        if (c->state == CONN_ESTABLISHED && c->snd_base < c->snd_next && !congestion_handled) {
            //只对最老的未确认段计 RTO，因为只有它最有可能导致拥塞。
            uint32_t seq = c->snd_base;
            size_t idx = seq % PROTO_WIN_SIZE;
            if (c->send_buf[idx].sent && !c->send_buf[idx].acked) {
               //只对最老的未确认段计 RTO
                if (now_ms - c->send_buf[idx].last_send_ts >= c->data_rto_ms) {
                    uint64_t new_rto = c->data_rto_ms * 2;
                    //RTO 的指数退避
                    if (new_rto > c->rto_max_ms) new_rto = c->rto_max_ms;
                    c->data_rto_ms = new_rto;
                    if (!c->in_fast_recovery) {
                        //拥塞控制反应：进入快速恢复状态
                        uint32_t new_ssthresh = c->cwnd / 2;
                        if (new_ssthresh < 2) new_ssthresh = 2;
                        c->ssthresh = new_ssthresh;
                        c->cwnd = 1;
                        c->dup_acks = 0;
                        c->ca_count = 0;
                        LOG_WARN("data RTO seq=%u cwnd->1 ssthresh=%u rto=%llums",
                                 seq, c->ssthresh, (unsigned long long)c->data_rto_ms);
                    } else {
                        LOG_WARN("data RTO seq=%u (fast recovery active, rto=%llums)",
                                 seq, (unsigned long long)c->data_rto_ms);
                    }
                    c->in_fast_recovery = false;
                    //重传最老的未确认段
                    send_data_segment(c, sockfd, seq);
                    //标记已经处理拥塞
                    congestion_handled = true;
                }
            }
        }
        ++i;
    }
}
//流量控制：把应用数据变成若干可发送的数据段，并在窗口允许的范围内把能发的都发出去
int conn_send_data(struct conn *c, socket_t sockfd, const uint8_t *data, uint32_t len) {
    if (!c || c->state != CONN_ESTABLISHED) return -1;
    uint32_t sent_bytes = 0;
    //计算当前允许发送的窗口大小
    uint32_t win_allow = c->snd_win;
    //只要 snd_next < snd_base + win_allow，就还能入队一段
    if (c->cwnd < win_allow) win_allow = c->cwnd;
    //填写发送缓冲区
    while (len > 0 && c->snd_next < c->snd_base + win_allow) {
        uint32_t seq = c->snd_next;
        //计算发送缓冲区索引，环形缓冲区
        size_t idx = seq % PROTO_WIN_SIZE;
        uint16_t chunk = (uint16_t)((len > PROTO_MAX_SEG_SIZE) ? PROTO_MAX_SEG_SIZE : len);
        c->send_buf[idx].in_use = true;
        c->send_buf[idx].sent = false;
        c->send_buf[idx].acked = false;
        c->send_buf[idx].len = chunk;
        memcpy(c->send_buf[idx].data, data + sent_bytes, chunk);
        c->snd_next++;
        sent_bytes += chunk;
        len -= chunk;
    }
    
    /* Try to flush immediately */
    //发送所有未发送的数据段
    win_allow = c->snd_win;
    if (c->cwnd < win_allow) win_allow = c->cwnd;
    for (uint32_t seq = c->snd_base; seq < c->snd_next && seq < c->snd_base + win_allow; ++seq) {
        size_t idx = seq % PROTO_WIN_SIZE;
        //封装成 PROTO_DATA 包，发送未发送的数据段
        if (c->send_buf[idx].in_use && !c->send_buf[idx].sent) {
            send_data_segment(c, sockfd, seq);
        }
    }
    return (int)sent_bytes;
}
//发送控制包，也就是非data包，比如SYN、SYN_ACK、FIN、ACK等
static void send_control(struct conn *c, socket_t sockfd, enum proto_type type, uint32_t ctrl_ack, const uint8_t *payload, uint32_t payload_len, uint64_t dcid_override) {
    struct proto_packet pkt = {
        .type = type,
        .flags = 0,
        .dcid = dcid_override ? dcid_override : c->peer_cid,
        .scid = c->my_cid,
        .ctrl_seq = c->ctrl_tx_next++,
        .ctrl_ack = ctrl_ack,
        .payload = payload,
        .payload_len = payload_len,
    };
    uint8_t buf[256];
    size_t out_len = 0;
    if (proto_encode(&pkt, buf, sizeof(buf), &out_len) != 0) return;
    sendto(sockfd, (const char *)buf, (int)out_len, 0, (struct sockaddr *)&c->peer_addr, c->peer_addrlen);
    uint64_t dcid = pkt.dcid;
    if (type == PROTO_SYN) {
        //发起连接时，发送SYN包，记录下发送时间
        LOG_INFO("send SYN cid=%llu->%llu seq=%u ack=%u", (unsigned long long)c->my_cid, (unsigned long long)dcid, pkt.ctrl_seq, pkt.ctrl_ack);
    } else if (type == PROTO_SYN_ACK) {
        //服务器端接受SYN请求后，发送SYN_ACK包
        LOG_INFO("send SYN_ACK cid=%llu->%llu seq=%u ack=%u", (unsigned long long)c->my_cid, (unsigned long long)dcid, pkt.ctrl_seq, pkt.ctrl_ack);
    } else if (type == PROTO_FIN) {
        //发送FIN包
        LOG_INFO("send FIN cid=%llu->%llu seq=%u ack=%u", (unsigned long long)c->my_cid, (unsigned long long)dcid, pkt.ctrl_seq, pkt.ctrl_ack);
    }
    //保存待确认的控制包状态
    c->pending.type = type;
    c->pending.ctrl_seq = pkt.ctrl_seq;
    c->pending.ctrl_ack = ctrl_ack;
    c->pending.payload_len = payload_len < sizeof(c->pending.payload) ? payload_len : sizeof(c->pending.payload);
    if (payload && c->pending.payload_len) memcpy(c->pending.payload, payload, c->pending.payload_len);
    c->has_pending = true;
    //启动重传定时器
    timer_start(&c->ctrl_timer, util_now_ms(), 300);
}
//发送ACK包
static void send_ack_only(struct conn *c, socket_t sockfd, uint32_t ctrl_ack) {
    struct proto_packet pkt = {
        .type = PROTO_ACK,
        .flags = 0,
        .dcid = c->peer_cid,
        .scid = c->my_cid,
        .ctrl_seq = c->ctrl_tx_next++,
        .ctrl_ack = ctrl_ack,
        .payload = NULL,
        .payload_len = 0,
    };
    uint8_t buf[128];
    size_t out_len = 0;
    if (proto_encode(&pkt, buf, sizeof(buf), &out_len) != 0) return;
    sendto(sockfd, (const char *)buf, (int)out_len, 0, (struct sockaddr *)&c->peer_addr, c->peer_addrlen);
    LOG_INFO("send ACK cid=%llu->%llu seq=%u ack=%u", (unsigned long long)c->my_cid, (unsigned long long)c->peer_cid, pkt.ctrl_seq, pkt.ctrl_ack);
}
//重传包
static void retransmit(struct conn *c, socket_t sockfd) {
    if (!c->has_pending) return;
    c->ctrl_retx_count++;
    struct proto_packet pkt = {
        .type = c->pending.type,
        .flags = 0,
        .dcid = c->peer_cid,
        .scid = c->my_cid,
        .ctrl_seq = c->pending.ctrl_seq,
        .ctrl_ack = c->pending.ctrl_ack,
        .payload = c->pending.payload,
        .payload_len = c->pending.payload_len,
    };
    uint8_t buf[256];
    size_t out_len = 0;
    if (proto_encode(&pkt, buf, sizeof(buf), &out_len) != 0) return;
    sendto(sockfd, (const char *)buf, (int)out_len, 0, (struct sockaddr *)&c->peer_addr, c->peer_addrlen);
    //做指数退避
    timer_backoff(&c->ctrl_timer, util_now_ms(), c->rto_max_ms);
    LOG_WARN("retransmit type=%d seq=%u rto=%llums", pkt.type, pkt.ctrl_seq, (unsigned long long)c->ctrl_timer.rto_ms);
}
//格式化地址
const char *conn_format_addr(const struct sockaddr_storage *addr, char *buf, size_t buflen) {
    util_addr_to_str(addr, buf, buflen);
    return buf;
}
//发送数据段，把“一个确定的 seq 的数据段”封装成 UDP 包并真正 sendto()s
static void send_data_segment(struct conn *c, socket_t sockfd, uint32_t seq) {
    //计算发送缓冲区索引，环形缓冲区
    size_t idx = seq % PROTO_WIN_SIZE;
    if (!c->send_buf[idx].in_use) return;
    if (c->send_buf[idx].sent && !c->send_buf[idx].acked) {
        c->data_retx_count++;
    }
    uint8_t payload[PROTO_MAX_SEG_SIZE + sizeof(struct proto_data_hdr)];
    //构造数据段头
    struct proto_data_hdr hdr = {
        .seg_seq = htonl(seq),
        .seg_len = htons(c->send_buf[idx].len),
        .flags = 0,
    };
    memcpy(payload, &hdr, sizeof(hdr));
    memcpy(payload + sizeof(hdr), c->send_buf[idx].data, c->send_buf[idx].len);
//构造数据包，准备发送，包括包头和数据段
    struct proto_packet pkt = {
        .type = PROTO_DATA,
        .flags = 0,
        .dcid = c->peer_cid,
        .scid = c->my_cid,
        .ctrl_seq = 0,
        .ctrl_ack = c->last_acked_ctrl,
        .payload = payload,
        .payload_len = (uint32_t)(sizeof(hdr) + c->send_buf[idx].len),
    };
    uint8_t buf[2048];
    size_t out_len = 0;
    //编码数据包
    if (proto_encode(&pkt, buf, sizeof(buf), &out_len) != 0) return;
    sendto(sockfd, (const char *)buf, (int)out_len, 0, (struct sockaddr *)&c->peer_addr, c->peer_addrlen);
    c->send_buf[idx].sent = true;
    c->send_buf[idx].last_send_ts = util_now_ms();
    if (seq > c->snd_highest) c->snd_highest = seq;
}
//发送ACK包，包含累计确认和SACK块
static void send_ack_for_rcv(struct conn *c, socket_t sockfd) {
    uint8_t payload[4 + 2 + 2 + PROTO_MAX_SACK * sizeof(struct proto_sack_block)];
   //先确定累计确认序列号
    uint32_t ack_seq = c->rcv_base;
    uint16_t sack_count = 0;
    /* Build SACK blocks for received segments beyond rcv_base */
    uint32_t seq_cursor = c->rcv_base;
    //扫描接收缓冲区，构造SACK块
    while (seq_cursor < c->rcv_base + c->rcv_win && sack_count < PROTO_MAX_SACK) {
        size_t idx = seq_cursor % PROTO_WIN_SIZE;
        //找到 received==true 但 seq > rcv_base 的段（说明“后面的段我收到了，但中间还有洞”）。
        if (c->recv_buf[idx].received && seq_cursor > c->rcv_base) {
            uint32_t start = seq_cursor;
            uint32_t end = start + 1;
            //找到连续收到的数据段范围，把连续的已收到段合并成区间 [start, end)，作为一个 struct proto_sack_block
            while (end < c->rcv_base + c->rcv_win) {
                size_t j = end % PROTO_WIN_SIZE;
                if (!c->recv_buf[j].received) break;
                end++;
            }
            struct proto_sack_block *blk = (struct proto_sack_block *)(payload + 8 + sack_count * sizeof(struct proto_sack_block));
            //htonl() 把 32 位整数从主机字节序转换为网络字节序（大端），保证不同端序的机器解析一致。
            blk->start = htonl(start);
            blk->end = htonl(end);
            sack_count++;
            seq_cursor = end;
        } else {
            seq_cursor++;
        }
    }
    //把 ACK payload 按定义的格式写出来
    uint32_t *ack_field = (uint32_t *)payload;
    *ack_field = htonl(ack_seq);
    uint16_t *cnt_field = (uint16_t *)(payload + 4);
    *cnt_field = htons(sack_count);
    uint16_t *reserved = (uint16_t *)(payload + 6);
    *reserved = 0;
    //封装成 PROTO_ACK 包并发回
    struct proto_packet pkt = {
        .type = PROTO_ACK,
        .flags = 0,
        .dcid = c->peer_cid,
        .scid = c->my_cid,
        .ctrl_seq = 0,
        .ctrl_ack = c->last_acked_ctrl,
        .payload = payload,
        .payload_len = (uint32_t)(8 + sack_count * sizeof(struct proto_sack_block)),
    };
    uint8_t buf[256];
    size_t out_len = 0;
    if (proto_encode(&pkt, buf, sizeof(buf), &out_len) != 0) return;
    sendto(sockfd, (const char *)buf, (int)out_len, 0, (struct sockaddr *)&c->peer_addr, c->peer_addrlen);
}//到521
//处理收到的数据包，流量控制
static void handle_data_pkt(struct conn *c, socket_t sockfd, const struct proto_packet *pkt) {
    if (pkt->payload_len < sizeof(struct proto_data_hdr)) {
        return;
    }
    struct proto_data_hdr hdr;
    memcpy(&hdr, pkt->payload, sizeof(hdr));
    uint32_t seq = ntohl(hdr.seg_seq);
    uint16_t seg_len = ntohs(hdr.seg_len);
    if (seg_len + sizeof(hdr) > pkt->payload_len || seg_len > PROTO_MAX_SEG_SIZE) {
        return;
    }
    //如果数据段序号小于已交付序号，说明是重复数据段，直接发送ACK确认当前接收状态
    if (seq < c->deliver_seq) {
        send_ack_for_rcv(c, sockfd);
        return;
    }
    //如果数据段序号超出接收窗口范围，直接发送ACK确认当前接收状态
   //告诉你当前 rcv_base，让你收敛到窗口内
    if (seq >= c->rcv_base + c->rcv_win) {
        send_ack_for_rcv(c, sockfd);
        return;
    }
    //保存收到的数据段到接收缓冲区
    size_t idx = seq % PROTO_WIN_SIZE;
    //乱序（窗口内但有洞），只保存未收到的数据段
    if (!c->recv_buf[idx].received) {
        c->recv_buf[idx].received = true;
        c->recv_buf[idx].len = seg_len;
        memcpy(c->recv_buf[idx].data, pkt->payload + sizeof(hdr), seg_len);
    }
    //按序到达（刚好是缺口）
    if (seq == c->rcv_base) {
        // “连续推进”：一旦缺口补齐，可能把之前缓存的乱序段一口气变成“按序前缀”，累计 ACK 会跳跃前进。
        while (1) {
            size_t i = c->rcv_base % PROTO_WIN_SIZE;
            
            if (!c->recv_buf[i].received) break;
            c->rcv_base++;
        }
    }
    /* Update deliverable count (contiguous from deliver_seq) */
    //只有当收到的 seg_seq == rcv_base（缺口补上）时，才进入 while 循环连续检查后面的槽：
    //只要 recv_buf[rcv_base % WIN].received==true 就 rcv_base++，一次把已经缓存的连续乱序段“吃掉”，累计 ACK 会跳跃前进。
    while (c->deliver_seq + c->app_recv_ready < c->rcv_base) {
        size_t i = (c->deliver_seq + c->app_recv_ready) % PROTO_WIN_SIZE;
        
        if (!c->recv_buf[i].received) break;
        c->app_recv_ready++;
    }
    send_ack_for_rcv(c, sockfd);
}
//处理收到的ACK包
static void handle_ack_pkt(struct conn *c, socket_t sockfd, const struct proto_packet *pkt) {
    if (pkt->payload_len < 8) return;
    //解析ACK包中的确认序列号和SACK块数量，累计确认：表示已按序收到 ack_seq-1
    uint32_t ack_seq = ntohl(*(uint32_t *)pkt->payload);
    uint16_t sack_count = ntohs(*(uint16_t *)(pkt->payload + 4));
    if (sack_count > PROTO_MAX_SACK) sack_count = PROTO_MAX_SACK;
    bool ack_advanced = ack_seq > c->last_ack_seq;
    LOG_INFO("recv ACK ack_seq=%u sack=%u cwnd=%u ssthresh=%u", ack_seq, sack_count, c->cwnd, c->ssthresh);
    //拥塞控制：重复 ACK 计数和快速恢复
    //计算重复ACK数量
    if (ack_advanced) {
        c->dup_acks = 0;
    } else if (ack_seq == c->last_ack_seq && ack_seq != 0) {
        c->dup_acks++;
        //连续出现 3 次（dupACK==3）且当前不在 FR。
        if (c->dup_acks == 3 && !c->in_fast_recovery) {
            enter_fast_recovery(c, sockfd);
        } else if (c->in_fast_recovery) {
            c->cwnd++;
        }
    }
    //
    if (ack_seq > c->last_ack_seq) c->last_ack_seq = ack_seq;
    if (ack_advanced) {
        c->data_rto_ms = c->data_rto_base_ms;
    }

    /* Cumulative ACK */
    //snd_base：当前最早“还没被确认(ACK)”的数据段序号，就说明前缀推进了，把 snd_base 到 ack_seq 之间的段都标记为已确认
    if (ack_seq > c->snd_base) {
        for (uint32_t seq = c->snd_base; seq < ack_seq; ++seq) {
            size_t idx = seq % PROTO_WIN_SIZE;
            c->send_buf[idx].acked = true;
            c->send_buf[idx].in_use = false;
        }
        c->snd_base = ack_seq;
    }
    /* SACK blocks */
    //标SACK blocks 不直接推进 snd_base（因为前缀可能还有洞）
    //把 SACK 覆盖的段 send_buf[seq].acked=true
    //超时扫描/重传时可以跳过已被 SACK 确认的段，只对缺口段重传
    const uint8_t *p = pkt->payload + 8;
    for (uint16_t i = 0; i < sack_count; ++i) {
        if (p + sizeof(struct proto_sack_block) > pkt->payload + pkt->payload_len) break;
        struct proto_sack_block blk;
        memcpy(&blk, p, sizeof(blk));
        uint32_t start = ntohl(blk.start);
        uint32_t end = ntohl(blk.end);
        for (uint32_t seq = start; seq < end; ++seq) {
            size_t idx = seq % PROTO_WIN_SIZE;
            c->send_buf[idx].acked = true;
            c->send_buf[idx].in_use = false;
        }
        p += sizeof(struct proto_sack_block);
    }
    //推进 snd_base 到第一个未确认的数据段
    while (c->snd_base < c->snd_next) {
        size_t idx = c->snd_base % PROTO_WIN_SIZE;
        if (!c->send_buf[idx].acked) break;
        c->snd_base++;
    }
    //拥塞控制算法
    /* Congestion control growth (new ACK) */
    if (ack_advanced && !c->in_fast_recovery) {
        //每个新 ACK 加 1，整体效果接近指数增
        if (c->cwnd < c->ssthresh) {
            c->cwnd += 1;
        } else {
            //拥塞避免，每收到一个 ACK 先累计一次，累计到 cwnd 次
            //（相当于一个窗口的数据都被确认了一遍≈一个 RTT），才 cwnd++
            c->ca_count += 1;
            if (c->ca_count >= c->cwnd) {
                c->cwnd += 1;
                c->ca_count = 0;
            }
        }
    }

    /* Fast recovery handling */
    //每来一个额外 dupACK，说明又有一个段到达接收端，发送端允许 cwnd++，尝试继续填管道。
    if (c->in_fast_recovery && ack_advanced) {
        //recover_seq=尚未得到确认的最大字节序号
        if (ack_seq >= c->recover_seq) {
            /* Recovery ACK */
            //说明进入 FR 前发出的那些段都已经被累计确认覆盖
            //退出 FR，cwnd = ssthresh，进入拥塞避免
            c->cwnd = c->ssthresh;
            c->in_fast_recovery = false;
            c->dup_acks = 0;
            LOG_INFO("fast recovery exit ack_seq=%u cwnd=%u ssthresh=%u", ack_seq, c->cwnd, c->ssthresh);
        } else {
            //ack_seq 前进了，但还没覆盖 recover_seq
            // 不退出 FR，继续重传下一个缺失的数据段
            size_t idx = c->snd_base % PROTO_WIN_SIZE;
            if (c->send_buf[idx].in_use && !c->send_buf[idx].acked) {
                send_data_segment(c, sockfd, c->snd_base);
            }
            c->cwnd = c->ssthresh + 3;
            LOG_INFO("partial ack ack_seq=%u recover_seq=%u cwnd=%u", ack_seq, c->recover_seq, c->cwnd);
        }
    }
}

static void enter_fast_recovery(struct conn *c, socket_t sockfd) {
    uint32_t new_ssthresh = c->cwnd / 2;
    //乘性减小
    //相当于(cwnd/2, 2)）。否则在小窗口或频繁丢包时阈值会被压到 1
    if (new_ssthresh < 2) new_ssthresh = 2;
    c->ssthresh = new_ssthresh;
    c->cwnd = c->ssthresh + 3;
    c->in_fast_recovery = true;
    //录进入 FR 时已发送到哪里，用于 NewReno 判断什么时候恢复完成。
    c->recover_seq = c->snd_highest;
    //重传最早未确认段
    if (c->snd_base < c->snd_next) {
        send_data_segment(c, sockfd, c->snd_base);
    }
    LOG_INFO("enter fast recovery cwnd=%u ssthresh=%u dup_acks=%u recover_seq=%u", c->cwnd, c->ssthresh, c->dup_acks, c->recover_seq);
}
//把“发送窗口内、已经入队但还没真正发出去”的数据段发出去。
void conn_flush_data(struct conn *c, socket_t sockfd) {
    if (!c || c->state != CONN_ESTABLISHED) return;
    uint32_t win_allow = c->snd_win;
    if (c->cwnd < win_allow) win_allow = c->cwnd;
    for (uint32_t seq = c->snd_base; seq < c->snd_next && seq < c->snd_base + win_allow; ++seq) {
        size_t idx = seq % PROTO_WIN_SIZE;
        if (c->send_buf[idx].in_use && !c->send_buf[idx].sent) {
            send_data_segment(c, sockfd, seq);
        }
    }
}
//在一个 UDP socket 上管理多条逻辑连接时，让每条已建立连接都能继续发送自己的窗口内数据。
void conn_flush_all(struct conn_table *ct, socket_t sockfd) {
    for (size_t i = 0; i < ct->count; ++i) {
        conn_flush_data(ct->items[i], sockfd);
    }
}
//从连接接收缓冲区读取下一个按序可用的数据段
int conn_recv_next(struct conn *c, uint8_t *buf, uint32_t cap) {
    if (!c || c->state != CONN_ESTABLISHED || c->app_recv_ready == 0) return 0;
    uint32_t seq = c->deliver_seq;
    size_t idx = seq % PROTO_WIN_SIZE;
    uint16_t len = c->recv_buf[idx].len;
    if (len > cap) len = (uint16_t)cap;
    memcpy(buf, c->recv_buf[idx].data, len);
    c->recv_buf[idx].received = false;
    c->deliver_seq++;
    c->app_recv_ready--;
    return len;
}
