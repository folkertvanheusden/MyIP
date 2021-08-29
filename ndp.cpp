// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <string.h>

#include "ndp.h"
#include "phys.h"
#include "utils.h"

ndp::ndp(stats *const s, const any_addr & mymac, const any_addr & myip6)
{
	ndp_entry_t me { uint64_t(-1), mymac };  // may never be purged
	ndp_cache.insert({ myip6, me });

        ndp_cache_req = s->register_stat("ndp_cache_req");
        ndp_cache_hit = s->register_stat("ndp_cache_hit");
        ndp_cache_store = s->register_stat("ndp_cache_store");
        ndp_cache_update = s->register_stat("ndp_cache_update");

	th = new std::thread(std::ref(*this));

	th2 = new std::thread(&ndp::cache_cleaner, this);
}

ndp::~ndp()
{
	stop_flag = true;
	th->join();
	delete th;
}

void ndp::operator()()
{
	set_thread_name("myip-ndp");

	while(!stop_flag) {
		std::unique_lock<std::mutex> lck(pkts_lock);

		using namespace std::chrono_literals;

		while(pkts.empty() && !stop_flag)
			pkts_cv.wait_for(lck, 500ms);

		if (pkts.empty() || stop_flag)
			continue;

		const packet *pkt = pkts.at(0);
		pkts.erase(pkts.begin());

		lck.unlock();

		// FIXME

		delete pkt;
	}
}

void ndp::update_cache(const any_addr & mac, const any_addr & ip6)
{
	assert(mac.get_len() == 6);

	const std::lock_guard<std::shared_mutex> lock(cache_lock);

	auto it = ndp_cache.find(ip6);

	if (it == ndp_cache.end()) {
		ndp_cache.insert({ ip6, { get_us(), mac } });

		stats_inc_counter(ndp_cache_store);
	}
	else {
		it->second.ts = get_us();
		it->second.addr = mac;

		stats_inc_counter(ndp_cache_update);
	}
}

any_addr * ndp::query_cache(const any_addr & ip6)
{
	const std::shared_lock<std::shared_mutex> lock(cache_lock);

	stats_inc_counter(ndp_cache_req);

	auto it = ndp_cache.find(ip6);
	if (it == ndp_cache.end()) {
		dolog(warning, "NDP: %s is not in the cache\n", ip6.to_str().c_str());
		return nullptr;
	}

	stats_inc_counter(ndp_cache_hit);

	return new any_addr(it->second.addr);
}

void ndp::cache_cleaner()
{
	uint64_t prev = get_us();

	while(!stop_flag) {
		myusleep(500000); // to allow quickly termination

		uint64_t now = get_us();
		if (now - prev < 30000000)
			continue;

		prev = now;

		std::vector<any_addr> delete_;

		const std::lock_guard<std::shared_mutex> lock(cache_lock);

		for(auto e : ndp_cache) {
			if (e.second.ts >= now)  // some are meant to stay forever
				continue;

			uint64_t age = now - e.second.ts;

			if (age >= 3600000000ll)  // older than an hour?
				delete_.push_back(e.first);
		}

		for(auto e : delete_) {
			dolog(debug, "NDP: forgetting %s\n", e.to_str().c_str());

			ndp_cache.erase(e);
		}
	}
}

void ndp::transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
}

void ndp::transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
}
