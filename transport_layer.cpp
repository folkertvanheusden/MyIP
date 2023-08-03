// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <chrono>

#include "transport_layer.h"
#include "log.h"


constexpr size_t pkts_max_size { 256 };

transport_layer::transport_layer(stats *const s, const std::string & stats_name)
{
	pkts = new fifo<packet *>(s, stats_name, pkts_max_size);
}

transport_layer::~transport_layer()
{
	delete pkts;
}

void transport_layer::queue_packet(packet *p)
{
	if (pkts->try_put(p) == false) {
		DOLOG(ll_debug, "IP-Protocol: queue full, packet dropped\n");

		delete p;
	}
}

uint16_t tcp_udp_checksum(const any_addr & src_addr, const any_addr & dst_addr, const bool tcp, const uint8_t *const tcp_payload, const int len)
{
	uint16_t checksum { 0 };

	if (dst_addr.get_family() == any_addr::ipv6) {  // IPv6
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
	else if (dst_addr.get_family() == any_addr::ipv4) {  // IPv4
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
	else {
		DOLOG(ll_debug, "tcp_udp_checksum: cannot handle \"%s\" to \"%s\"\n", src_addr.to_str().c_str(), dst_addr.to_str().c_str());
	}

	return checksum;
}
