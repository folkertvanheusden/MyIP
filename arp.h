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
	std::map<any_addr, any_addr> arp_cache;

	const any_addr mymac;
	const any_addr myip;

	uint64_t *arp_requests { nullptr }, *arp_for_me { nullptr };
	uint64_t *arp_cache_req { nullptr }, *arp_cache_hit { nullptr };

public:
	arp(stats *const s, const any_addr & mymac, const any_addr & ip);
	virtual ~arp();

	void update_cache(const any_addr & mac, const any_addr & ip);
	any_addr * query_cache(const any_addr & ip);

	void transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;
	void transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;

	// using this for ARP packets does not make sense
	virtual int get_max_packet_size() const override { return pdev->get_max_packet_size() - 26 /* 26 = size of ARP */; }

	void operator()() override;
};
