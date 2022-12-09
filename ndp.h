// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <assert.h>
#include <map>
#include <shared_mutex>

#include "address_cache.h"
#include "network_layer.h"
#include "phys.h"
#include "router.h"
#include "stats.h"


typedef struct {
	uint64_t ts;
	any_addr addr;
} ndp_entry_t;

class ndp : public address_cache
{
private:
        uint64_t *ndp_cache_req { nullptr };
	uint64_t *ndp_cache_hit { nullptr };

public:
	ndp(stats *const s, router *const r);
	virtual ~ndp();

	void add_static_entry(phys *const interface, const any_addr & mac, const any_addr & ip);
};
