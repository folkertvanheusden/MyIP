// (C) 2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <stdint.h>

static constexpr int up_size = 100;

class fifo_stats
{
private:
	uint64_t counters[up_size] { 0 };
	int divider { 1 };

public:
	fifo_stats(const int range_max);
	virtual ~fifo_stats();

	void count(const int value);

	int get_size() const { return up_size; };

	uint64_t get_counter(const int idx) const { return counters[idx]; }
};
