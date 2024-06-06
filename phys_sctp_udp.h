// (C) 2020-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <map>
#include <string>
#include <thread>
#include <netinet/in.h>

#include "any_addr.h"
#include "phys.h"
#include "network_layer.h"
#include "stats.h"


class phys_sctp_udp : public phys
{
private:
	const any_addr my_addr;  // IPv4 address matching the port
	int            fd      { -1 };

public:
	phys_sctp_udp(const size_t dev_index, stats *const s, const any_addr & my_mac, const any_addr & my_addr, const int port, router *const r);
	phys_sctp_udp(const phys_sctp_udp &) = delete;
	virtual ~phys_sctp_udp();

	bool transmit_packet(const any_addr & dest_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size) override;

	any_addr::addr_family get_phys_type() override { return any_addr::mac; }

	void operator()() override;
};
