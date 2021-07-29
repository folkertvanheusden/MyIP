// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under AGPL v3.0
#pragma once
#include <cstring>
#include <stdint.h>
#include <utility>
#include <sys/time.h>

class packet
{
private:
	const struct timeval tv { 0, 0 };

	uint8_t *src_addr;
	int src_size;

	uint8_t *dst_addr;
	int dst_size;

	uint8_t *data;
	int size;

	// this is required for ICMP: it needs certain fields from the source (IP-)header
	uint8_t *header;
	int header_size;

public:
	packet(const uint8_t *src_addr, const int src_size, const uint8_t *dst_addr, const int dst_size, const uint8_t *const in, const int size, const uint8_t *const header, const int header_size);
	packet(const struct timeval & tv, const uint8_t *src_addr, const int src_size, const uint8_t *dst_addr, const int dst_size, const uint8_t *const in, const int size, const uint8_t *const header, const int header_size);
	virtual ~packet();

	uint8_t *const get_data() const { return data; }
	int get_size() const { return size; }
	std::pair<const uint8_t *, int> get_payload() const { return { data, size }; }

	std::pair<const uint8_t *, int> get_src_addr() const { return { src_addr, src_size }; }

	std::pair<const uint8_t *, int> get_dst_addr() const { return { dst_addr, dst_size }; }

	std::pair<const uint8_t *, int> get_header() const { return { header, header_size }; }

	struct timeval get_recv_ts() const { return tv; }

	packet *duplicate() const;
};
