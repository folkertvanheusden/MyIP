#include <stdexcept>
#include <stdint.h>

#include "buffer.h"


uint16_t get_net_short(const uint8_t *const p)
{
	return (p[0] << 8) | p[1];
}

uint32_t get_net_long(const uint8_t *const p)
{
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

uint64_t get_net_long_long(const uint8_t *const p)
{
	uint64_t out = 0;

	for(int i=0; i<8; i++) {
		out <<= 8;
		out |= p[i];
	}

	return out;
}

buffer::buffer(const uint8_t *p, const int size) : p(p), size(size)
{
}

buffer::buffer(const buffer & b) : p(b.get_pointer()), size(b.get_size())
{
}

buffer::~buffer()
{
}

uint8_t  buffer::get_byte()
{
	if (o >= size)
		throw std::out_of_range("buffer::get_byte");

	return p[o++];
}

uint16_t buffer::get_net_short()
{
	if (o + 2 > size)
		throw std::out_of_range("buffer::get_net_short");

	uint16_t temp = ::get_net_short(&p[o]);
	o += 2;

	return temp;
}

uint32_t buffer::get_net_long()
{
	if (o + 4 > size)
		throw std::out_of_range("buffer::get_net_long");

	uint32_t temp = ::get_net_long(&p[o]);
	o += 4;

	return temp;
}

uint64_t buffer::get_net_long_long()
{
	if (o + 8 > size)
		throw std::out_of_range("buffer::get_net_long_long");

	uint64_t temp = ::get_net_long_long(&p[o]);
	o += 8;

	return temp;
}

float buffer::get_net_float()
{
	if (o + 4 > size)
		throw std::out_of_range("buffer::get_net_float");

	uint32_t temp = ::get_net_long(&p[o]);
	o += 4;

	return *reinterpret_cast<float *>(&temp);
}

double buffer::get_net_double()
{
	if (o + 8 > size)
		throw std::out_of_range("buffer::get_net_double");

	uint64_t temp = ::get_net_long_long(&p[o]);
	o += 8;

	return *reinterpret_cast<double *>(&temp);
}

buffer buffer::get_segment(const int len)
{
	if (o + len > size)
		throw std::out_of_range("buffer::get_segment");

	buffer temp = buffer(&p[o], len);
	o += len;

	return temp;
}

std::string buffer::get_string(const int len)
{
	if (o + len > size)
		throw std::out_of_range("buffer::get_segment");

	std::string temp = std::string(reinterpret_cast<const char *>(&p[o]), len);
	o += len;

	return temp;
}

void buffer::seek(const int len)
{
	if (o + len > size)
		throw std::out_of_range("buffer::seek");

	o += len;
}

bool buffer::end_reached() const
{
	return o == size;
}

int buffer::get_n_bytes_left() const
{
	return size - o;
}

const uint8_t *buffer::get_bytes(const int len)
{
	if (o + len > size)
		throw std::out_of_range("buffer::get_bytes");

	int temp = o;
	o += len;

	return &p[temp];
}

uint64_t get_variable_size_integer(buffer & data_source, const int len)
{
	uint64_t out = 0;

	for(int i=0; i<len; i++) {
		out <<= 8;
		out |= data_source.get_byte();
	}

	return out;
}
