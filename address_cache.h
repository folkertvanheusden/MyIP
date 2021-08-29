// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <map>
#include <shared_mutex>

#include "phys.h"
#include "protocol.h"
#include "stats.h"

typedef struct {
	uint64_t ts;
	any_addr addr;
} address_entry_t;

class address_cache
{
protected:
	std::shared_mutex cache_lock;
	std::map<any_addr, address_entry_t> cache;

	const any_addr mymac;
	const any_addr myip;

	std::atomic_bool stop_flag2;
	std::thread *th2;

	uint64_t *address_cache_requests { nullptr }, *address_cache_for_me { nullptr };
	uint64_t *address_cache_req { nullptr }, *address_cache_hit { nullptr };
        uint64_t *address_cache_store { nullptr }, *address_cache_update { nullptr };

	void cache_cleaner();

public:
	address_cache(stats *const s, const any_addr & mymac, const any_addr & ip);
	virtual ~address_cache();

	void update_cache(const any_addr & mac, const any_addr & ip);
	virtual any_addr * query_cache(const any_addr & ip);
};
