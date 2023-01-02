// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include "packet.h"
#include "utils.h"


packet::packet(const timespec & ts_in, const any_addr & src_mac_addr, const any_addr & src_addr, const any_addr & dst_addr, const uint8_t *const in, const int size, const uint8_t *const header, const int header_size, const std::string & log_prefix) : ts(ts_in), src_mac_addr(src_mac_addr), src_addr(src_addr), dst_addr(dst_addr), log_prefix(log_prefix)
{
	this->size = size;
	data = ::duplicate(in, size);

	this->header_size = header_size;
	this->header = header_size ? ::duplicate(header, header_size) : nullptr;
}

packet::packet(const timespec & ts_in, const any_addr & src_addr, const any_addr & dst_addr, const uint8_t *const in, const int size, const uint8_t *const header, const int header_size, const std::string & log_prefix) : ts(ts_in), src_mac_addr(src_addr), src_addr(src_addr), dst_addr(dst_addr), log_prefix(log_prefix)
{
	this->size = size;
	data = ::duplicate(in, size);

	this->header_size = header_size;
	this->header = header_size ? ::duplicate(header, header_size) : nullptr;
}

packet::~packet()
{
	delete [] header;
	delete [] data;
}

packet *packet::duplicate() const
{
	return new packet(ts, src_mac_addr, src_addr, dst_addr, data, size, header, header_size, log_prefix);
}
