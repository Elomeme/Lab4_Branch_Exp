#include "conn.h"
#include "io_loop.h"
#include "util.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog) {
    fprintf(stderr, "usage: %s [--win <N>] <host> <port> <file_path>\n", prog);
    fprintf(stderr, "  N is in segments, max %u\n", (unsigned)PROTO_WIN_SIZE);
}

static int resolve_addr(const char *host, const char *port, struct sockaddr_storage *out, socklen_t *outlen) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) return -1;
    memcpy(out, res->ai_addr, res->ai_addrlen);
    *outlen = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

int main(int argc, char **argv) {
    uint32_t win = PROTO_WIN_SIZE;
    int argi = 1;
    while (argi < argc && strncmp(argv[argi], "--", 2) == 0) {
        if (strcmp(argv[argi], "--win") == 0) {
            if (argi + 1 >= argc) {
                usage(argv[0]);
                return 1;
            }
            long v = strtol(argv[argi + 1], NULL, 10);
            if (v < 1) v = 1;
            if (v > (long)PROTO_WIN_SIZE) v = (long)PROTO_WIN_SIZE;
            win = (uint32_t)v;
            argi += 2;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (argc - argi < 3) {
        usage(argv[0]);
        return 1;
    }
    const char *host = argv[argi + 0];
    const char *port = argv[argi + 1];
    const char *file_path = argv[argi + 2];

    int exit_code = 1;
    socket_t sockfd = SOCKET_INVALID;
    FILE *fp = NULL;

#ifdef _WIN32
    WSADATA wsa;
    int wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (wsa_rc != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", wsa_rc);
        return 1;
    }
#endif
    srand((unsigned)util_now_ms());

    struct sockaddr_storage peer;
    socklen_t peerlen;
    if (resolve_addr(host, port, &peer, &peerlen) != 0) {
        fprintf(stderr, "resolve failed\n");
        goto cleanup;
    }
    sockfd = socket(peer.ss_family, SOCK_DGRAM, 0);
    if (!socket_valid(sockfd)) {
        fprintf(stderr, "socket failed (err=%d)\n", socket_last_error());
        goto cleanup;
    }

    struct conn_table ct;
    conn_table_init(&ct);
    conn_table_set_default_win(&ct, win);
    struct conn *c = conn_client_connect(&ct, sockfd, &peer, peerlen);
    if (!c) {
        fprintf(stderr, "connect setup failed\n");
        goto cleanup;
    }

    while (c && c->state != CONN_ESTABLISHED) {
        io_poll_once(sockfd, &ct, 100, false);
        c = conn_lookup(&ct, c->my_cid);
    }
    if (!c) {
        fprintf(stderr, "connection failed during handshake\n");
        goto cleanup;
    }

    fp = fopen(file_path, "rb");
    if (!fp) {
        perror("fopen");
        goto cleanup;
    }

    uint8_t buf[PROTO_MAX_SEG_SIZE];
    size_t nread = 0;
    uint64_t total_bytes = 0;
    uint64_t start_ms = util_now_ms();
    while ((nread = fread(buf, 1, sizeof(buf), fp)) > 0) {
        total_bytes += (uint64_t)nread;
        size_t sent = 0;
        while (sent < nread) {
            /* Backpressure: wait if fixed send window full */
            while (c && c->snd_next >= c->snd_base + c->snd_win) {
                io_poll_once(sockfd, &ct, 50, false);
            }
            sent += conn_send_data(c, sockfd, buf + sent, (uint32_t)(nread - sent));
            io_poll_once(sockfd, &ct, 10, false);
            c = conn_lookup(&ct, c->my_cid);
            if (!c || c->state != CONN_ESTABLISHED) break;
        }
        if (!c || c->state != CONN_ESTABLISHED) {
            fprintf(stderr, "connection lost while sending\n");
            goto cleanup;
        }
    }

    /* 等待所有已发送段被 ACK */
    while (c && c->snd_base < c->snd_next) {
        io_poll_once(sockfd, &ct, 50, false);
    }
    uint64_t end_ms = util_now_ms();
    uint64_t elapsed_ms = (end_ms >= start_ms) ? (end_ms - start_ms) : 0;
    double sec = elapsed_ms / 1000.0;
    double kbps = sec > 0 ? (total_bytes / 1024.0) / sec : 0.0;
    fprintf(stderr,
            "[RESULT] win=%u bytes=%llu time_ms=%llu throughput_kBps=%.2f data_retx=%u ctrl_retx=%u\n",
            (unsigned)win,
            (unsigned long long)total_bytes,
            (unsigned long long)elapsed_ms,
            kbps,
            c ? c->data_retx_count : 0u,
            c ? c->ctrl_retx_count : 0u);

    conn_client_close(c, sockfd);

    while (conn_lookup(&ct, c->my_cid)) {
        io_poll_once(sockfd, &ct, 100, false);
    }
    exit_code = 0;

cleanup:
    if (fp) fclose(fp);
    if (socket_valid(sockfd)) socket_close(sockfd);
#ifdef _WIN32
    WSACleanup();
#endif
    LOG_INFO("client exit");
    return exit_code;
}
