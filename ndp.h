// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <assert.h>
#include <map>
#include <shared_mutex>

#include "phys.h"
#include "network_layer.h"
#include "address_cache.h"
#include "stats.h"

typedef struct {
	uint64_t ts;
	any_addr addr;
} ndp_entry_t;

class ndp : public network_layer, public address_cache
{
private:
        uint64_t *ndp_cache_req { nullptr }, *ndp_cache_hit { nullptr };

	std::thread *ndp_th { nullptr };
	std::atomic_bool ndp_stop_flag { false };

public:
	ndp(stats *const s);
	virtual ~ndp();

	any_addr get_addr() const override { assert(false); return any_addr(); }

	void add_static_entry(phys *const interface, const any_addr & mac, const any_addr & ip);

	bool transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t network_layer, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;
	bool transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t network_layer, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;

	// using this for ARP packets does not make sense
	virtual int get_max_packet_size() const override { return -1; }

	void operator()() override;
};
