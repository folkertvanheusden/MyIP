// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <string.h>

#include "ndp.h"
#include "phys.h"
#include "utils.h"

ndp::ndp(stats *const s, const any_addr & mymac, const any_addr & myip6)
{
	update_cache(mymac, myip6);

        ndp_cache_req = s->register_stat("ndp_cache_req");
        ndp_cache_hit = s->register_stat("ndp_cache_hit");

	th = new std::thread(std::ref(*this));
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
	const std::lock_guard<std::shared_mutex> lock(cache_lock);

	auto it = ndp_cache.find(ip6);

	if (it == ndp_cache.end())
		ndp_cache.insert({ ip6, mac });
	else
		it->second = mac;
}

any_addr * ndp::query_cache(const any_addr & ip6)
{
	const std::shared_lock<std::shared_mutex> lock(cache_lock);

	stats_inc_counter(ndp_cache_req);

	auto it = ndp_cache.find(ip6);
	if (it == ndp_cache.end()) {
		dolog("NDP: %s is not in the cache\n", ip6.to_str().c_str());
		return nullptr;
	}

	stats_inc_counter(ndp_cache_hit);

	return new any_addr(it->second);
}

void ndp::transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
	// FIXME
}
