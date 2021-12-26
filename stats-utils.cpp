#include <stdint.h>
#include <string>

#include "utils.h"

std::string stats_to_json(const uint8_t *const p, const int size)
{
	std::string out;

	const uint8_t *const p_end = &p[size];
	const uint8_t *cur_p = p;

	while(cur_p < p_end && cur_p[16]) {
		uint64_t *cnt_p = (uint64_t *)cur_p;
		uint64_t *cnt_p2 = (uint64_t *)(cur_p + 8);

		if (out.empty())
			out = "{ ";
		else
			out += ", ";

		out += myformat("\"%s\" : ", &cur_p[16]);

		if (*cnt_p2)
			out += myformat("%f", *cnt_p / double(*cnt_p2));
		else
			out += myformat("%lu", *cnt_p);

		cur_p += 48;
	}

	out += " }";

	return out;
}
