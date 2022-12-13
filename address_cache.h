// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <map>
#include <shared_mutex>

#include "phys.h"
#include "network_layer.h"
#include "stats.h"


typedef struct {
	uint64_t ts;
	any_addr addr;
	phys    *interface;
} address_entry_t;

class address_cache
{
protected:
	std::shared_mutex cache_lock;
	std::map<any_addr, address_entry_t> cache;

	std::atomic_bool cleaner_stop_flag { false   };
	std::thread     *cleaner_th        { nullptr };

	uint64_t *address_cache_requests { nullptr }, *address_cache_for_me { nullptr };
	uint64_t *address_cache_req      { nullptr }, *address_cache_hit    { nullptr };
        uint64_t *address_cache_store    { nullptr }, *address_cache_update { nullptr };

	void cache_cleaner();

public:
	address_cache(stats *const s);
	virtual ~address_cache();

	void update_cache(const any_addr & mac, const any_addr & ip, phys *const interface, const bool static_entry = false);

	void add_static_entry(phys *const interface, const any_addr & mac, const any_addr & ip);

	virtual std::pair<phys *, any_addr *> query_cache(const any_addr & ip, const bool static_entry = false);

	void dump_cache();
};
