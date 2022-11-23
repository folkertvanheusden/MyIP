// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include "application.h"
#include "stats.h"


port_handler_t http_get_handler(stats *const s, const std::string & web_root, const std::string & log_file, const bool is_https);
