// (C) 2020-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <optional>

#include "any_addr.h"
#include "mac_resolver.h"
#include "stats.h"


class icmp6;

class ndp : public mac_resolver
{
private:
	icmp6    *icmp6_        { nullptr };

        uint64_t *ndp_cache_req { nullptr };
	uint64_t *ndp_cache_hit { nullptr };

	bool send_request(const any_addr & ip, const any_addr::addr_family af) override;

	std::optional<any_addr> check_special_ip_addresses(const any_addr & ip, const any_addr::addr_family family) override;

public:
	ndp(stats *const s);
	virtual ~ndp();

	void register_icmp6(icmp6 *const icmp6_) { this->icmp6_ = icmp6_; }

	void operator()() override;
};
