// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <map>
#include <mutex>
#include <stdint.h>
#include <string>
#include <vector>

#include "fifo-stats.h"

void stats_inc_counter(uint64_t *const p);
void stats_set(uint64_t *const p, const uint64_t value);
void stats_add_average(uint64_t *const p, const int val);

typedef struct _stats_t_{
	uint64_t *p { nullptr };
	std::string oid;

	_stats_t_() {
	}
} stats_t;

typedef struct _oid_t_ {
	stats_t s;
	int index;
	std::map<std::string, _oid_t_> children;
} oid_t;

class stats
{
private:
	const int size;
	int fd { -1 };
	uint8_t *p { nullptr };
	int len { 0 };

	std::map<std::string, stats_t> lut;

	std::map<std::string, oid_t> lut_oid;

	std::map<std::string, fifo_stats *> fs;

	mutable std::mutex lock;

public:
	stats(const int size);
	virtual ~stats();

	uint64_t * register_stat(const std::string & name, const std::string & oid = "");

	void register_fifo_stats(const std::string & name, fifo_stats *const fs);
	std::vector<std::pair<const std::string, const fifo_stats *> > get_fifo_stats() const;

	uint64_t * find_by_oid(const std::string & oid);
	std::string find_next_oid(const std::string & oid);

	std::string to_json() const;
};
