// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <map>
#include <string>
#include <thread>

#include "protocol.h"
#include "stats.h"

class phys
{
private:
	int fd { -1 };
	std::thread *th { nullptr };
	std::atomic_bool stop_flag { false };

	uint64_t *phys_recv_frame { nullptr };
	uint64_t *phys_invl_frame { nullptr };
	uint64_t *phys_ign_frame { nullptr };
	uint64_t *phys_transmit { nullptr };

	std::map<uint16_t, protocol *> prot_map;

public:
	phys(stats *const s, const std::string & dev_name);
	virtual ~phys();

	void register_protocol(const uint16_t ether_type, protocol *const p);

	void transmit_packet(const uint8_t *dest_mac, const uint8_t *src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size);

	void operator()();
};
