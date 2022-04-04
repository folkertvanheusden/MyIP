// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <map>
#include <mutex>
#include <stdint.h>
#include <string>
#include <vector>

#include "fifo-stats.h"
#include "snmp-data.h"


void stats_inc_counter(uint64_t *const p);
void stats_add_counter(uint64_t *const p, const uint64_t value);
void stats_set(uint64_t *const p, const uint64_t value);
void stats_add_average(uint64_t *const p, const int value);

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
	const int        size { 0 };
	snmp_data *const sd   { nullptr };
	int              fd   { -1 };
	uint8_t         *p    { nullptr };
	int              len  { 0 };

	std::map<std::string, stats_t>      lut;

	std::map<std::string, fifo_stats *> fs;

	mutable std::mutex lock;

public:
	stats(const int size, snmp_data *const sd);
	virtual ~stats();

	uint64_t * register_stat(const std::string & name, const std::string & oid = "", const snmp_integer::snmp_integer_type type = snmp_integer::si_integer);

	void register_fifo_stats(const std::string & name, fifo_stats *const fs);
	std::vector<std::pair<const std::string, const fifo_stats *> > get_fifo_stats() const;

	std::string to_json() const;
};
