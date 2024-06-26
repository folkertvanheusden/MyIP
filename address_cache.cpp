// (C) 2020-2024 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <string.h>

#include "address_cache.h"
#include "log.h"
#include "phys.h"
#include "time.h"


std::shared_mutex address_cache::cache_lock;
std::map<any_addr, address_cache::address_entry_t> address_cache::cache;
std::map<any_addr, phys *> address_cache::mac_cache;

address_cache::address_cache(stats *const s)
{
	// 1.3.6.1.4.1.57850.1.7: address cache
	address_cache_requests = s->register_stat("address_cache_requests", "1.3.6.1.4.1.57850.1.7.1");
	address_cache_for_me   = s->register_stat("address_cache_for_me", "1.3.6.1.4.1.57850.1.7.2");
	address_cache_req      = s->register_stat("address_cache_req", "1.3.6.1.4.1.57850.1.7.3");
	address_cache_hit      = s->register_stat("address_cache_hit", "1.3.6.1.4.1.57850.1.7.4");
	address_cache_store    = s->register_stat("address_cache_store", "1.3.6.1.4.1.57850.1.7.5");
	address_cache_update   = s->register_stat("address_cache_cache_update", "1.3.6.1.4.1.57850.1.7.6");

	cleaner_th = new std::thread(&address_cache::cache_cleaner, this);
}

address_cache::~address_cache()
{
	cleaner_stop.signal_stop();

	cleaner_th->join();
	delete cleaner_th;
}

void address_cache::update_cache(const any_addr & mac, const any_addr & ip, phys *const interface, const bool static_entry)
{
	const std::lock_guard<std::shared_mutex> lock(cache_lock);

	assert(mac.get_family() == any_addr::mac  || mac.get_family() == any_addr::ax25);
	assert(ip.get_family()  == any_addr::ipv4 || ip.get_family()  == any_addr::ipv6);

	auto it = cache.find(ip);

	if (it == cache.end()) {
		cache.insert({ ip, { static_entry ? 0 : get_us(), mac, interface } });
		stats_inc_counter(address_cache_store);
	}
	else {
		if (it->second.ts != 0) {  // do not overwrite static entries
			it->second = { static_entry ? 0 : get_us(), mac, interface };
			stats_inc_counter(address_cache_update);
		}
	}

	auto it_mac = mac_cache.find(mac);

	if (it_mac == mac_cache.end())  // TODO cleanup, like regular cache
		mac_cache.insert({ mac, interface });
}

void address_cache::add_static_entry(phys *const interface, const any_addr & mac, const any_addr & ip)
{
        update_cache(mac, ip, interface, true);
}

std::pair<phys *, any_addr *> address_cache::query_cache(const any_addr & ip, const bool static_entry)
{
	const std::shared_lock<std::shared_mutex> lock(cache_lock);

	stats_inc_counter(address_cache_req);

	auto it = cache.find(ip);
	if (it == cache.end()) {
		DOLOG(ll_warning, "address_cache: %s is not in the cache\n", ip.to_str().c_str());
		return { nullptr, nullptr };
	}

	if (static_entry && it->second.ts != 0) {
		DOLOG(ll_warning, "address_cache: %s is not a static entry\n", ip.to_str().c_str());
		return { nullptr, nullptr };
	}

	stats_inc_counter(address_cache_hit);

	return { it->second.interface, new any_addr(it->second.addr) };
}

phys * address_cache::query_mac_cache(const any_addr & mac)
{
	const std::shared_lock<std::shared_mutex> lock(cache_lock);

	stats_inc_counter(address_cache_req);

	auto it = mac_cache.find(mac);
	if (it == mac_cache.end()) {
		DOLOG(ll_warning, "address_cache: MAC %s is not in the cache\n", mac.to_str().c_str());
		return nullptr;
	}

	return it->second;
}

void address_cache::cache_cleaner()
{
	set_thread_name("myip-acc");

	for(;;) {
		if (cleaner_stop.sleep(30000))
			break;

		uint64_t now = get_us();

		std::vector<any_addr> delete_;

		const std::lock_guard<std::shared_mutex> lock(cache_lock);

		for(auto & e : cache) {
			if (e.second.ts == 0)  // some are meant to stay forever
				continue;

			uint64_t age = now - e.second.ts;

			if (age >= 3600000000ll)  // older than an hour?
				delete_.push_back(e.first);
		}

		for(auto & e : delete_) {
			DOLOG(ll_debug, "address_cache: forgetting %s\n", e.to_str().c_str());

			cache.erase(e);
		}
	}
}

void address_cache::dump_cache()
{
	uint64_t now = get_us();

	const std::shared_lock<std::shared_mutex> lock(cache_lock);

	for(auto & e : cache) {
		if (e.second.ts)
			DOLOG(ll_debug, "address_cache: %s (%.3f) %s %s\n", e.first.to_str().c_str(), (now - e.second.ts) / 1000000., e.second.addr.to_str().c_str(), e.second.interface->to_str().c_str());
		else
			DOLOG(ll_debug, "address_cache: %s %s %s\n", e.first.to_str().c_str(), e.second.addr.to_str().c_str(), e.second.interface->to_str().c_str());
	}
}
