// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <optional>

#include "any_addr.h"
#include "mac_resolver.h"
#include "stats.h"


typedef struct {
	uint64_t ts;
	any_addr addr;
} ndp_entry_t;

class ndp : public mac_resolver
{
private:
        uint64_t *ndp_cache_req { nullptr };
	uint64_t *ndp_cache_hit { nullptr };

	bool send_request(const any_addr & ip) override;

	std::optional<any_addr> check_special_ip_addresses(const any_addr & ip) override;

public:
	ndp(stats *const s);
	virtual ~ndp();

	void operator()() override;
};
