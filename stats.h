// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <map>
#include <mutex>
#include <stdint.h>
#include <string>

void stats_inc_counter(uint64_t *const p);
void stats_add_average(uint64_t *const p, const int val);

class stats
{
private:
	const int size;
	int fd { -1 };
	uint8_t *p { nullptr };
	int len { 0 };

	std::map<std::string, uint64_t *> lut;
	std::mutex lock;

public:
	stats(const int size);
	virtual ~stats();

	uint64_t * register_stat(const std::string & name);

	std::string to_json() const;
};
