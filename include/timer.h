#pragma once

#include <stdint.h>
#include <stdbool.h>

struct timer {
    uint64_t deadline_ms;
    uint64_t rto_ms;
    uint32_t retries;
    bool armed;
};

void timer_start(struct timer *t, uint64_t now_ms, uint64_t rto_ms);
void timer_stop(struct timer *t);
bool timer_expired(const struct timer *t, uint64_t now_ms);
void timer_backoff(struct timer *t, uint64_t now_ms, uint64_t rto_max_ms);
