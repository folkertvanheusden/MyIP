// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include "stats.h"
#include "tcp.h"

tcp_port_handler_t http_get_handler(stats *const s, const std::string & web_root, const std::string & log_file);
