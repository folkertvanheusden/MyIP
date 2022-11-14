// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <stdint.h>
#include <string>

#include "fifo-stats.h"
#include "utils.h"

std::string stats_to_json(const uint8_t *const p, const std::vector<std::pair<const std::string, const fifo_stats *> > & fs, const int size)
{
	std::string out;

	const uint8_t *const p_end = &p[size];
	const uint8_t *cur_p = p;

	bool first_gen = true;
	while(cur_p < p_end && cur_p[16]) {
		uint64_t *cnt_p = (uint64_t *)cur_p;
		uint64_t *cnt_p2 = (uint64_t *)(cur_p + 8);

		if (first_gen) {
			out = "{ ";
			first_gen = false;
		}
		else {
			out += ", ";
		}

		out += myformat("\"%s\" : ", &cur_p[16]);

		if (*cnt_p2)
			out += myformat("%f", *cnt_p / double(*cnt_p2));
		else
			out += myformat("%lu", *cnt_p);

		cur_p += 48;
	}

	out += ", \"fifo\":[";
	bool first_fs = true;
	for(auto & pair : fs) {
		if (first_fs)
			first_fs = false;
		else
			out += ", ";

		out += myformat("{ \"name\":\"%s\", \"values\":[", pair.first.c_str());

		int n_counters = pair.second->get_size();
		for(int i=0; i<n_counters; i++) {
			if (i)
				out += ", ";

			out += myformat("%lu", pair.second->get_counter(i));
		}

		out += "] }";
	}
	out += "]";

	out += " }";

	return out;
}
