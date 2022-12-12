// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include "any_addr.h"
#include "transport_layer.h"
#include "stats.h"


class icmp : public transport_layer
{
public:
	icmp(stats *const s);
	virtual ~icmp();

	virtual void send_destination_port_unreachable(const any_addr & dst_ip, const any_addr & src_ip, const packet *const p) const = 0;

	virtual void operator()() override = 0;

	virtual void send_ttl_exceeded(const packet *const pkt) const = 0;
};
