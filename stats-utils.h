// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include "fifo-stats.h"

std::string stats_to_json(const uint8_t *const p, const std::vector<std::pair<const std::string, const fifo_stats *> > & fs, const int size);
