// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <cstring>
#include <stdint.h>
#include <utility>
#include <sys/time.h>

#include "any_addr.h"

class packet
{
private:
	const struct timeval tv { 0, 0 };

	const any_addr src_addr, dst_addr;

	uint8_t *data;
	int size;

	// this is required for ICMP: it needs certain fields from the source (IP-)header
	uint8_t *header;
	int header_size;

public:
	packet(const any_addr & src_addr, const any_addr & dst_addr, const uint8_t *const in, const int size, const uint8_t *const header, const int header_size);
	packet(const struct timeval & tv, const any_addr & src_addr, const any_addr & dst_addr, const uint8_t *const in, const int size, const uint8_t *const header, const int header_size);
	virtual ~packet();

	uint8_t *get_data() const { return data; }
	std::pair<const uint8_t *, int> get_payload() const { return { data, size }; }

	int get_size() const { return size; }

	const any_addr & get_src_addr() const { return src_addr; }

	const any_addr & get_dst_addr() const { return dst_addr; }

	std::pair<const uint8_t *, int> get_header() const { return { header, header_size }; }

	struct timeval get_recv_ts() const { return tv; }

	packet *duplicate() const;
};
