#pragma once
#include <stdint.h>
#include <vector>

#include "any_addr.h"
#include "buffer_in.h"


class buffer_out
{
private:
	std::vector<uint8_t> buffer;

public:
	buffer_out();
	virtual ~buffer_out();

	void add_net_byte (const uint8_t  b);
	void add_net_short(const uint16_t s);
	void add_net_long (const uint32_t l);

	// used by length fields
	size_t add_net_short(const uint16_t s, const ssize_t offset);
	size_t add_net_long (const uint32_t s, const ssize_t offset);

	void add_any_addr(const any_addr & a);

	void add_buffer_out(const buffer_out & o);
	void add_buffer_in (      buffer_in  & i);

	const std::vector<uint8_t> & get_payload() const;

	size_t         get_size() const;
	const uint8_t *get_content() const;
};
