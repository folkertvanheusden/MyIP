// (C) 2020-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#pragma once
#include <atomic>
#include <map>
#include <string>
#include <thread>

#include "any_addr.h"
#include "phys.h"
#include "network_layer.h"
#include "stats.h"


class phys_tap : public phys
{
private:
	int fd { -1 };

public:
	phys_tap(const size_t dev_index, stats *const s, const std::string & dev_name, const int uid, const int gid, const int mtu_size, router *const r);
	phys_tap(const phys_tap &) = delete;
	virtual ~phys_tap();

	bool transmit_packet(const any_addr & dest_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size) override;

	any_addr::addr_family get_phys_type() override { return any_addr::mac; }

	void operator()() override;
};

bool process_ethernet_frame(const timespec & ts, const std::vector<uint8_t> & buffer, std::map<uint16_t, network_layer *> *const prot_map, router *const r, phys *const source_phys);
