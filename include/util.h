#pragma once

#include <stdint.h>
#include <stddef.h>

#include "platform.h"

uint64_t util_random64(void);
uint64_t util_now_ms(void);
void util_addr_to_str(const struct sockaddr_storage *addr, char *buf, size_t len);

uint64_t util_test(void);

