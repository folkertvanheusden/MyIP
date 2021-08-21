// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <map>
#include <shared_mutex>

#include "phys.h"
#include "protocol.h"
#include "stats.h"

class arp : public protocol
{
private:
	std::shared_mutex cache_lock;
	std::map<uint32_t, uint8_t *> arp_cache;

	uint8_t mymac[6];
	uint8_t myip[4];

	uint64_t *arp_requests { nullptr }, *arp_for_me { nullptr };
	uint64_t *arp_cache_req { nullptr }, *arp_cache_hit { nullptr };

public:
	arp(stats *const s, const uint8_t mymac[6], const uint8_t myip[4]);
	virtual ~arp();

	void update_cache(const uint8_t *const mac, const uint8_t *const ip);
	uint8_t * query_cache(const uint8_t *const ip);

	// using this for ARP packets does not make sense
	int get_max_packet_size() override { return pdev->get_max_packet_size() - 26 /* 26 = size of ARP */; }

	void operator()() override;
};
