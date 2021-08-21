// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <functional>
#include <map>

#include "ip_protocol.h"
#include "packet.h"
#include "stats.h"

class icmp;
class ipv4;

class udp : public ip_protocol
{
private:
	icmp *const icmp_;

	// src ip, src port, dest ip (=local), dest port, payload-packet
	std::map<int, std::function<void(const uint8_t *, int, const uint8_t *, int, packet *)> > callbacks;

	uint64_t *udp_requests { nullptr };
	uint64_t *udp_refused { nullptr };

public:
	udp(stats *const s, icmp *const icmp_);
	virtual ~udp();

	void add_handler(const int port, std::function<void(const uint8_t *, int, const uint8_t *, int, packet *)> h);

	void transmit_packet(const uint8_t *dst_ip, const int dst_port, const uint8_t *src_ip, const int src_port, const uint8_t *payload, const size_t pl_size);

	virtual void operator()();
};
