// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include "packet.h"
#include "utils.h"

packet::packet(const struct timeval & tv_in, const uint8_t *src_addr, const int src_size, const uint8_t *dst_addr, const int dst_size, const uint8_t *const in, const int size, const uint8_t *const header, const int header_size) : tv(tv_in)
{
	this->src_size = src_size;
	this->src_addr = ::duplicate(src_addr, src_size);

	this->dst_size = dst_size;
	this->dst_addr = ::duplicate(dst_addr, dst_size);

	this->size = size;
	data = ::duplicate(in, size);

	this->header_size = header_size;
	this->header = ::duplicate(header, header_size);
}

packet::packet(const uint8_t *src_addr, const int src_size, const uint8_t *dst_addr, const int dst_size, const uint8_t *const in, const int size, const uint8_t *const header, const int header_size)
{
	this->src_size = src_size;
	this->src_addr = ::duplicate(src_addr, src_size);

	this->dst_size = dst_size;
	this->dst_addr = ::duplicate(dst_addr, dst_size);

	this->size = size;
	data = ::duplicate(in, size);

	this->header_size = header_size;
	this->header = ::duplicate(header, header_size);
}

packet::~packet()
{
	delete [] header;
	delete [] data;
	delete [] dst_addr;
	delete [] src_addr;
}

packet *packet::duplicate() const
{
	return new packet(tv, src_addr, src_size, dst_addr, dst_size, data, size, header, header_size);
}
