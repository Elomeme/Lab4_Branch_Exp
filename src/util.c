#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

uint64_t util_random64(void) {
    uint64_t v = 0;
    for (int i = 0; i < 4; ++i) {
        v = (v << 16) ^ (uint64_t)(rand() & 0xffff);
    }
    return v;
}

uint64_t util_now_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
#endif
}

void util_addr_to_str(const struct sockaddr_storage *addr, char *buf, size_t len) {
    void *src = NULL;
    uint16_t port = 0;
    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
        src = (void *)&a->sin_addr;
        port = ntohs(a->sin_port);
    } else if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)addr;
        src = (void *)&a6->sin6_addr;
        port = ntohs(a6->sin6_port);
    }
    if (src) {
        inet_ntop(addr->ss_family, src, buf, (socklen_t)len);
        size_t used = strlen(buf);
        snprintf(buf + used, len - used, ":%u", port);
    } else {
        snprintf(buf, len, "unknown");
    }
}
