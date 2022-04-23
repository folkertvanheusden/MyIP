#pragma once

#include <stdint.h>
#include <string>


class buffer
{
private:
	const uint8_t *const p { nullptr };
	const int            size { 0 };
	int                  o { 0 };

	const uint8_t * get_pointer() const { return p; };
	int             get_size()    const { return size; };

public:
	buffer(const uint8_t *p, const int size);
	buffer(const buffer & b);
	virtual ~buffer();

	uint8_t     get_byte();
	uint16_t    get_net_short();  // 2 bytes
	uint32_t    get_net_long();  // 4 bytes
	uint64_t    get_net_long_long();  // 8 bytes
	float       get_net_float();
	double      get_net_double();
	const uint8_t * get_bytes(const int len);

	buffer      get_segment(const int len);

	std::string get_string(const int len);

	void        seek(const int len);

	bool        end_reached() const;
	int         get_n_bytes_left() const;
};

uint64_t get_variable_size_integer(buffer & data_source, const int len);
