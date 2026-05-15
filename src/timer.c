#include "timer.h"

void timer_start(struct timer *t, uint64_t now_ms, uint64_t rto_ms) {
    t->rto_ms = rto_ms;
    t->deadline_ms = now_ms + rto_ms;
    t->retries = 0;
    t->armed = true;
}

void timer_stop(struct timer *t) {
    t->armed = false;
}

bool timer_expired(const struct timer *t, uint64_t now_ms) {
    return t->armed && now_ms >= t->deadline_ms;
}

void timer_backoff(struct timer *t, uint64_t now_ms, uint64_t rto_max_ms) {
    if (!t->armed) return;
    uint64_t next = t->rto_ms * 2;
    if (next > rto_max_ms) next = rto_max_ms;
    t->rto_ms = next;
    t->deadline_ms = now_ms + t->rto_ms;
    t->retries += 1;
}
