// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <map>
#include <string>
#include <thread>

#include "any_addr.h"
#include "phys.h"
#include "protocol.h"
#include "stats.h"


class phys_promiscuous : public phys
{
private:
	int fd        { -1 };
	int ifr_index { -1 };

public:
	phys_promiscuous(const size_t dev_index, stats *const s, const std::string & dev_name);
	phys_promiscuous(const phys_promiscuous &) = delete;
	virtual ~phys_promiscuous();

	bool transmit_packet(const any_addr & dest_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size) override;

	void operator()() override;
};
