#pragma once
#include <stdint.h>
#include <vector>

#include "buffer_in.h"


class buffer_out
{
private:
	std::vector<uint8_t> buffer;

public:
	buffer_out();
	virtual ~buffer_out();

	void add_net_byte (const uint8_t b);
	void add_net_short(const uint8_t s);
	void add_net_long (const uint8_t l);

	void add_buffer_out(const buffer_out & o);
	void add_buffer_in (      buffer_in  & i);

	const std::vector<uint8_t> & get_payload() const;

	size_t         get_size() const;
	const uint8_t *get_content() const;
};
