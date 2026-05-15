#include "io_loop.h"
#include "proto.h"
#include "conn.h"
#include "util.h"
#include "log.h"
#include <string.h>
//基于 select 的事件循环，每一轮负责接收 UDP 数据，自建传输层主循环
int io_poll_once(socket_t sockfd, struct conn_table *ct, int timeout_ms, bool server_mode) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
#ifdef _WIN32
    int ret = select(0, &rfds, NULL, NULL, &tv);
#else
    int ret = select(sockfd + 1, &rfds, NULL, NULL, &tv);
#endif
    if (ret > 0 && FD_ISSET(sockfd, &rfds)) {
        uint8_t buf[2048];
        struct sockaddr_storage peer;
        socklen_t peerlen = sizeof(peer);
#ifdef _WIN32
        int n = recvfrom(sockfd, (char *)buf, (int)sizeof(buf), 0, (struct sockaddr *)&peer, &peerlen);
#else
        int n = (int)recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peerlen);
#endif
        if (n > 0) {
            struct proto_packet pkt;
            if (proto_decode(buf, (size_t)n, &pkt) == 0) {
                //服务器模式下，处理 SYN 包建立连接
                if (server_mode && pkt.type == PROTO_SYN && pkt.dcid == 0) {
                    conn_server_accept_syn(ct, sockfd, &pkt, &peer, peerlen);//101
                } else {
                    //查找对应连接，处理后续包
                    struct conn *c = conn_lookup(ct, pkt.dcid);
                    //存在连接则处理包
                    if (c) {
                        conn_handle_packet(ct, c, sockfd, &pkt);
                    } else {
                        LOG_WARN("drop packet for unknown cid=%llu", (unsigned long long)pkt.dcid);
                    }
                }
            }
        }
    }
    //处理定时器事件
    conn_tick_all(ct, sockfd, util_now_ms());
    conn_flush_all(ct, sockfd);
    return ret;
}

void io_flush_senders(socket_t sockfd, struct conn_table *ct) {
    conn_flush_all(ct, sockfd);
}
