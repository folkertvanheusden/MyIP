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
	const any_addr gw_mac, my_mac, my_ip;

	uint64_t *arp_requests { nullptr }, *arp_for_me { nullptr };

	std::thread *arp_th { nullptr };
	std::atomic_bool arp_stop_flag { false };

public:
	arp(stats *const s, const any_addr & mymac, const any_addr & myip, const any_addr & gw_mac);
	virtual ~arp();

	any_addr get_addr() const override { return my_mac; }

	void add_static_entry(phys *const interface, const any_addr & mac, const any_addr & ip);

	bool transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;
	bool transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;

	// using this for ARP packets does not make sense
	virtual int get_max_packet_size() const override { return default_pdev->get_max_packet_size() - 26 /* 26 = size of ARP */; }

	std::pair<phys *, any_addr *> query_cache(const any_addr & ip) override;

	void operator()() override;
};
