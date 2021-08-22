// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <map>
#include <shared_mutex>

#include "phys.h"
#include "protocol.h"
#include "stats.h"

class ndp : public protocol
{
private:
	std::shared_mutex cache_lock;
	std::map<any_addr, any_addr> ndp_cache;

        uint64_t *ndp_cache_req { nullptr }, *ndp_cache_hit { nullptr };

public:
	ndp(stats *const s, const any_addr & mymac, const any_addr & ip6);
	virtual ~ndp();

	void update_cache(const any_addr & mac, const any_addr & ip6);
	any_addr * query_cache(const any_addr & ip6);

	void transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template = nullptr);

	// using this for ARP packets does not make sense
	virtual int get_max_packet_size() const override { return -1; }

	void operator()() override;
};
