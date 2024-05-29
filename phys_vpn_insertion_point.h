// (C) 2024 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#pragma once
#include <atomic>
#include <map>
#include <string>
#include <termios.h>
#include <thread>

#include "any_addr.h"
#include "phys.h"
#include "network_layer.h"
#include "stats.h"
#include "vpn.h"

class phys_vpn_insertion_point : public phys
{
private:
	vpn *v { nullptr };

public:
	phys_vpn_insertion_point(const size_t dev_index, stats *const s, const std::string & dev_name, router *const r);
	phys_vpn_insertion_point(const phys_vpn_insertion_point &) = delete;
	virtual ~phys_vpn_insertion_point();

	void start() override;

	// into the vpn
	bool transmit_packet(const any_addr & dest_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size) override;

	any_addr::addr_family get_phys_type() override { return any_addr::mac; }

	void configure_endpoint(vpn *const v);
	// from the vpn
	bool insert_packet(const uint16_t ether_type, const uint8_t *const payload, const size_t pl_size);

	void operator()() override;
};
