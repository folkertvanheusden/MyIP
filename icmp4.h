// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include "any_addr.h"
#include "icmp.h"
#include "stats.h"

class icmp4 : public icmp
{
private:
	uint64_t *icmp_requests { nullptr }, *icmp_req_ping { nullptr };
	uint64_t *icmp_transmit { nullptr };

	void send_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t type, const uint8_t code, const packet *const p) const;

public:
	icmp4(stats *const s, const int n_threads);
	virtual ~icmp4();

	void send_destination_port_unreachable(const any_addr & dst_ip, const any_addr & src_ip, const packet *const p) const override;

	void send_ttl_exceeded(const packet *const pkt) const override;

	void operator()() override;
};
