#include <stdint.h>
#include <string>

#include "utils.h"

std::string stats_to_json(const uint8_t *const p, const int size)
{
	std::string out;

	const uint8_t *const p_end = &p[size];
	const uint8_t *cur_p = p;

	while(cur_p < p_end && cur_p[8]) {
		uint64_t *cnt_p = (uint64_t *)cur_p;

		if (out.empty())
			out = "{ ";
		else
			out += ", ";

		out += myformat("\"%s\" : ", &cur_p[8]);
		out += myformat("%lu", *cnt_p);

		cur_p += 32;
	}

	out += " }";

	return out;
}
