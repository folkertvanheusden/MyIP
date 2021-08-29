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
} ndp_entry_t;

class ndp : public protocol, public address_cache
{
        uint64_t *ndp_cache_req { nullptr }, *ndp_cache_hit { nullptr };

public:
	ndp(stats *const s, const any_addr & mymac, const any_addr & ip6);
	virtual ~ndp();

	void transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;
	void transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;

	// using this for ARP packets does not make sense
	virtual int get_max_packet_size() const override { return -1; }

	void operator()() override;
};
