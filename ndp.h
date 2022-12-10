// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <assert.h>
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
} ndp_entry_t;

class ndp : public address_cache, public mac_resolver
{
private:
        uint64_t *ndp_cache_req { nullptr };
	uint64_t *ndp_cache_hit { nullptr };

public:
	ndp(stats *const s);
	virtual ~ndp();

	any_addr get_mac(const any_addr & ip) override;
};
