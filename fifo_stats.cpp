// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include "fifo_stats.h"

fifo_stats::fifo_stats(const int range_max)
{
	divider = (range_max + 1) / up_size;
}

fifo_stats::~fifo_stats()
{
}

void fifo_stats::count(const int value)
{
	counters[value / divider]++;
}
