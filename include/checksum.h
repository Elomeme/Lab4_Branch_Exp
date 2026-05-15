#pragma once

#include <stddef.h>
#include <stdint.h>

/* 16-bit one's complement checksum (RFC 1071 style). */
uint16_t checksum16(const void *data, size_t len);
