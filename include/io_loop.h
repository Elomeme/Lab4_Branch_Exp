#pragma once

#include <stdbool.h>
#include "platform.h"
#include "conn.h"

/* Poll once: recv dispatch + timer tick. */
int io_poll_once(socket_t sockfd, struct conn_table *ct, int timeout_ms, bool server_mode);

/* Attempt to flush pending DATA (respecting window) for all conns. */
void io_flush_senders(socket_t sockfd, struct conn_table *ct);
