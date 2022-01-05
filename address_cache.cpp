// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <string.h>

#include "address_cache.h"
#include "phys.h"
#include "utils.h"

address_cache::address_cache(stats *const s)
{
	// 1.3.6.1.2.1.4.57850.1.7: address cache
	address_cache_requests = s->register_stat("address_cache_requests", "1.3.6.1.2.1.4.57850.1.7.1");
	address_cache_for_me   = s->register_stat("address_cache_for_me", "1.3.6.1.2.1.4.57850.1.7.2");
	address_cache_req      = s->register_stat("address_cache_req", "1.3.6.1.2.1.4.57850.1.7.3");
	address_cache_hit      = s->register_stat("address_cache_hit", "1.3.6.1.2.1.4.57850.1.7.4");
	address_cache_store    = s->register_stat("address_cache_store", "1.3.6.1.2.1.4.57850.1.7.5");
	address_cache_update   = s->register_stat("address_cache_cache_update", "1.3.6.1.2.1.4.57850.1.7.6");

	cleaner_th = new std::thread(&address_cache::cache_cleaner, this);
}

address_cache::~address_cache()
{
	cleaner_stop_flag = true;

	cleaner_th->join();
	delete cleaner_th;
}

void address_cache::update_cache(const any_addr & mac, const any_addr & ip, phys *const interface, const bool static_entry)
{
	const std::lock_guard<std::shared_mutex> lock(cache_lock);

	auto it = cache.find(ip);

	if (it == cache.end()) {
		cache.insert({ ip, { static_entry ? 0 : get_us(), mac, interface } });
		stats_inc_counter(address_cache_store);
	}
	else {
		it->second = { static_entry ? 0 : get_us(), mac, interface };
		stats_inc_counter(address_cache_update);
	}
}

std::pair<phys *, any_addr *> address_cache::query_cache(const any_addr & ip)
{
	const std::shared_lock<std::shared_mutex> lock(cache_lock);

	stats_inc_counter(address_cache_req);

	auto it = cache.find(ip);
	if (it == cache.end()) {
		DOLOG(warning, "address_cache: %s is not in the cache\n", ip.to_str().c_str());
		return { nullptr, nullptr };
	}

	stats_inc_counter(address_cache_hit);

	return { it->second.interface, new any_addr(it->second.addr) };
}

void address_cache::cache_cleaner()
{
	uint64_t prev = get_us();

	while(!cleaner_stop_flag) {
		myusleep(500000); // to allow quickly termination

		uint64_t now = get_us();
		if (now - prev < 30000000)
			continue;

		prev = now;

		std::vector<any_addr> delete_;

		const std::lock_guard<std::shared_mutex> lock(cache_lock);

		for(auto e : cache) {
			if (e.second.ts == 0)  // some are meant to stay forever
				continue;

			uint64_t age = now - e.second.ts;

			if (age >= 3600000000ll)  // older than an hour?
				delete_.push_back(e.first);
		}

		for(auto e : delete_) {
			DOLOG(debug, "address_cache: forgetting %s\n", e.to_str().c_str());

			cache.erase(e);
		}
	}
}
