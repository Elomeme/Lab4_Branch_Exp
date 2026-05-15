#include "io_loop.h"
#include "conn.h"
#include "log.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog) {
    fprintf(stderr, "usage: %s [--win <N>] <port> [output_file]\n", prog);
    fprintf(stderr, "  N is in segments, max %u\n", (unsigned)PROTO_WIN_SIZE);
}

static socket_t make_server_socket(const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *res = NULL;
    int rc = getaddrinfo(NULL, port, &hints, &res);
    if (rc != 0) return SOCKET_INVALID;
    socket_t sockfd = SOCKET_INVALID;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (!socket_valid(sockfd)) continue;
        if (p->ai_family == AF_INET6) {
            int v6only = 0;
            setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, (int)sizeof(v6only));
        }
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == 0) break;
        socket_close(sockfd);
        sockfd = SOCKET_INVALID;
    }
    freeaddrinfo(res);
    return sockfd;
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

    if (argc - argi < 1) {
        usage(argv[0]);
        return 1;
    }
#ifdef _WIN32
    WSADATA wsa;
    int wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (wsa_rc != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", wsa_rc);
        return 1;
    }
#endif
    srand((unsigned)util_now_ms());

    const char *port = argv[argi + 0];
    const char *out_path = (argc - argi >= 2) ? argv[argi + 1] : "received.bin";

    socket_t sockfd = make_server_socket(port);
    if (!socket_valid(sockfd)) {
        fprintf(stderr, "bind failed (err=%d)\n", socket_last_error());
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    LOG_INFO("server listening on port %s (win=%u)", port, (unsigned)win);
    struct conn_table ct;
    conn_table_init(&ct);
    conn_table_set_default_win(&ct, win);
    FILE *fp = fopen(out_path, "wb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    for (;;) {
        io_poll_once(sockfd, &ct, 200, true);
        /* Drain received data from all established conns */
        for (size_t i = 0; i < ct.count; ++i) {
            struct conn *c = ct.items[i];
            if (!c || c->state != CONN_ESTABLISHED) continue;
            uint8_t buf[PROTO_MAX_SEG_SIZE];
            int n = 0;
            while ((n = conn_recv_next(c, buf, sizeof(buf))) > 0) {
                fwrite(buf, 1, (size_t)n, fp);
                fflush(fp);
            }
        }
    }
#ifdef _WIN32
    WSACleanup();
#endif
    if (fp) fclose(fp);
    socket_close(sockfd);
    return 0;
}
