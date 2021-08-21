// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include "ip_protocol.h"
#include "stats.h"

class icmp : public ip_protocol
{
private:
	uint64_t *icmp_requests { nullptr }, *icmp_req_ping { nullptr };
	uint64_t *icmp_transmit { nullptr };

public:
	icmp(stats *const s);
	virtual ~icmp();

	void send_packet(const uint8_t *const dst_ip, const uint8_t *const src_ip, const uint8_t type, const uint8_t code, const packet *const p) const;

	virtual void operator()();
};
