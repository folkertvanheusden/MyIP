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

void buffer_out::add_net_short(const uint16_t s)
{
	buffer.push_back(s >> 8);
	buffer.push_back(s);
}

void buffer_out::add_net_long(const uint32_t l)
{
	buffer.push_back(l >> 24);
	buffer.push_back(l >> 16);
	buffer.push_back(l >>  8);
	buffer.push_back(l);
}

size_t buffer_out::add_net_short(const uint16_t s, const ssize_t offset)
{
	if (offset != -1) {
		buffer.at(offset + 0) = s >> 8;
		buffer.at(offset + 1) = s;

		return offset;
	}

	size_t o = buffer.size();

	buffer.push_back(s >> 8);
	buffer.push_back(s);

	return o;
}

size_t buffer_out::add_net_long(const uint32_t l, const ssize_t offset)
{
	if (offset != -1) {
		buffer.at(offset + 0) = l >> 24;
		buffer.at(offset + 1) = l >> 16;
		buffer.at(offset + 2) = l >>  8;
		buffer.at(offset + 3) = l;

		return offset;
	}

	size_t o = buffer.size();

	buffer.push_back(l >> 24);
	buffer.push_back(l >> 16);
	buffer.push_back(l >>  8);
	buffer.push_back(l);

	return o;
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

void buffer_out::add_padding(const int m)
{
	int padding = m - (buffer.size() % m);

	if (padding != m) {
		while(padding)
			buffer.push_back(0), padding--;
	}
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
