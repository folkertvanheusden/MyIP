// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <map>
#include <shared_mutex>

#include "address_cache.h"
#include "mac_resolver.h"
#include "network_layer.h"
#include "phys.h"
#include "stats.h"


typedef struct {
	uint64_t ts;
	any_addr addr;
} arp_entry_t;

class arp : public address_cache, public mac_resolver
{
private:
	const any_addr gw_mac;
	const any_addr my_mac;
	const any_addr my_ip;

	uint64_t *arp_requests { nullptr };
	uint64_t *arp_for_me   { nullptr };

	std::thread     *arp_th        { nullptr };
	std::atomic_bool arp_stop_flag { false   };

	phys *const interface  { nullptr };

	bool send_request(const any_addr & ip);

public:
	arp(stats *const s, phys *const interface, const any_addr & mymac, const any_addr & myip, const any_addr & gw_mac);
	virtual ~arp();

	std::optional<any_addr> get_mac(const any_addr & ip) override;

	void operator()() override;
};
