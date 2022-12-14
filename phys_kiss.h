// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#pragma once
#include <atomic>
#include <map>
#include <string>
#include <thread>

#include "any_addr.h"
#include "phys.h"
#include "network_layer.h"
#include "stats.h"

class phys_kiss : public phys
{
private:
	const any_addr & my_callsign;

	int              fd          { -1 };

public:
	phys_kiss(const size_t dev_index, stats *const s, const std::string & dev_file, const int tty_bps, const any_addr & my_callsign);
	phys_kiss(const phys_kiss &) = delete;
	virtual ~phys_kiss();

	bool transmit_packet(const any_addr & dest_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size) override;

	virtual any_addr::addr_family get_phys_type() override { return any_addr::ax25; }

	void operator()() override;
};
