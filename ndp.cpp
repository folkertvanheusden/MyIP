// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <string.h>

#include "any_addr.h"
#include "icmp6.h"
#include "ndp.h"
#include "phys.h"


ndp::ndp(stats *const s) : mac_resolver(s, nullptr)
{
	// 1.3.6.1.4.1.57850.1.9: ndp
        ndp_cache_req = s->register_stat("ndp_cache_req", "1.3.6.1.4.1.57850.1.9.1");
        ndp_cache_hit = s->register_stat("ndp_cache_hit", "1.3.6.1.4.1.57850.1.9.2");
}

ndp::~ndp()
{
}

void ndp::operator()()
{
}

bool ndp::send_request(const any_addr & ip, const any_addr::addr_family af)
{
	if (icmp6_) {
		icmp6_->send_packet_neighbor_solicitation(ip);

		return true;
	}

	DOLOG(ll_error, "ndp::send_request: no icmp6 instance available\n");

	return false;
}

std::optional<any_addr> ndp::check_special_ip_addresses(const any_addr & ip, const any_addr::addr_family family)
{
	return { };
}
