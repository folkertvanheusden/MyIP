#pragma once

#include <stdint.h>
#include <string>
#include <vector>


class buffer_in
{
private:
	const uint8_t *p    { nullptr };
	int            size { 0 };
	int            o    { 0 };

	const uint8_t * get_pointer() const { return p; };
	int             get_size()    const { return size; };

public:
	buffer_in();
	buffer_in(const uint8_t *p, const int size);
	buffer_in(const buffer_in & b);
	virtual ~buffer_in();

	uint8_t     get_net_byte();
	uint16_t    get_net_short();  // 2 bytes
	uint32_t    get_net_long();  // 4 bytes
	uint64_t    get_net_long_long();  // 8 bytes
	float       get_net_float();
	double      get_net_double();
	const uint8_t * get_bytes(const int len);

	buffer_in      get_segment(const int len);

	std::string get_string(const int len);

	void        seek(const int len);

	bool        end_reached() const;
	int         get_n_bytes_left() const;

	const std::vector<uint8_t> peek() const;
};

uint64_t get_variable_size_integer(buffer_in & data_source, const int len);
