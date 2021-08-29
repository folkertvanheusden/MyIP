// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <map>
#include <shared_mutex>

#include "phys.h"
#include "protocol.h"
#include "address_cache.h"
#include "stats.h"

typedef struct {
	uint64_t ts;
	any_addr addr;
} arp_entry_t;

class arp : public protocol, public address_cache
{
private:
	uint64_t *arp_requests { nullptr }, *arp_for_me { nullptr };

public:
	arp(stats *const s, const any_addr & mymac, const any_addr & ip);
	virtual ~arp();

	void transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;
	void transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;

	// using this for ARP packets does not make sense
	virtual int get_max_packet_size() const override { return pdev->get_max_packet_size() - 26 /* 26 = size of ARP */; }

	any_addr * query_cache(const any_addr & ip);

	void operator()() override;
};
