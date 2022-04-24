#include "buffer_out.h"

buffer_out::buffer_out()
{
}

buffer_out::~buffer_out()
{
}

void buffer_out::add_net_byte(const uint8_t b)
{
	buffer.push_back(b);
}

void buffer_out::add_net_short(const uint8_t s)
{
	buffer.push_back(s >> 8);
	buffer.push_back(s);
}

void buffer_out::add_net_long(const uint8_t l)
{
	buffer.push_back(l >> 24);
	buffer.push_back(l >> 16);
	buffer.push_back(l >>  8);
	buffer.push_back(l);
}

void buffer_out::add_any_addr(const any_addr & a)
{
	int len = a.get_len();

	for(int i=0; i<len; i++)
		buffer.push_back(a[i]);
}

void buffer_out::add_buffer_out(const buffer_out & o)
{
	for(auto b : o.get_payload())
		buffer.push_back(b);
}

void buffer_out::add_buffer_in(buffer_in & i)
{
	int n = i.get_n_bytes_left();

	for(int k=0; k<n; k++)
		buffer.push_back(i.get_net_byte());
}

const std::vector<uint8_t> & buffer_out::get_payload() const
{
	return buffer;
}

size_t buffer_out::get_size() const
{
	return buffer.size();
}

const uint8_t *buffer_out::get_content() const
{
	return buffer.data();
}
