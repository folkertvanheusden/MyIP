// (C) 2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include "stats.h"
#include "tcp.h"


port_handler_t tcp_proxy_get_handler(stats *const s, const any_addr & dest_ip, const int dest_port);
