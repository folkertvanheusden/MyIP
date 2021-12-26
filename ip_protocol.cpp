// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <chrono>

#include "ip_protocol.h"
#include "utils.h"

constexpr size_t pkts_max_size { 512 };

ip_protocol::ip_protocol(stats *const s, const std::string & stats_name)
{
	pkts = new fifo<const packet *>(s, stats_name, pkts_max_size);
}

ip_protocol::~ip_protocol()
{
	delete pkts;
}

void ip_protocol::queue_packet(const packet *p)
{
	if (!pkts->try_put(p))
		dolog(debug, "IP-Protocol: packet dropped\n");
}

uint16_t tcp_udp_checksum(const any_addr & src_addr, const any_addr & dst_addr, const bool tcp, const uint8_t *const tcp_payload, const int len)
{
	uint16_t checksum { 0 };

	if (dst_addr.get_len() == 16) {  // IPv6
		size_t temp_len = 40 + len + (len & 1);
		uint8_t *temp = new uint8_t[temp_len]();

		src_addr.get(&temp[0], 16);

		dst_addr.get(&temp[16], 16);

		temp[32] = len >> 24;
		temp[33] = len >> 16;
		temp[34] = len >>  8;
		temp[35] = len;

		temp[39] = tcp ? 0x06 : 0x11;

		memcpy(&temp[40], tcp_payload, len);

		checksum = ip_checksum((const uint16_t *)temp, temp_len / 2);

		delete [] temp;
	}
	else {  // IPv4
		size_t temp_len = 12 + len + (len & 1);
		uint8_t *temp = new uint8_t[temp_len]();

		src_addr.get(&temp[0], 4);

		dst_addr.get(&temp[4], 4);

		temp[9] = tcp ? 0x06 : 0x11;

		temp[10] = len >> 8; // TCP len
		temp[11] = len;

		memcpy(&temp[12], tcp_payload, len);

		checksum = ip_checksum((const uint16_t *)temp, temp_len / 2);

		delete [] temp;
	}

	return checksum;
}
