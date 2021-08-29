// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <string.h>

#include "arp.h"
#include "phys.h"
#include "utils.h"

arp::arp(stats *const s, const any_addr & mymac, const any_addr & myip) : mymac(mymac), myip(myip)
{
	arp_requests  = s->register_stat("arp_requests");
	arp_for_me    = s->register_stat("arp_for_me");
	arp_cache_req = s->register_stat("arp_cache_req");
	arp_cache_hit = s->register_stat("arp_cache_hit");

	update_cache(mymac, myip);

	th = new std::thread(std::ref(*this));
}

arp::~arp()
{
	stop_flag = true;
	th->join();
	delete th;
}

void arp::operator()()
{
	set_thread_name("myip-arp");

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

		stats_inc_counter(arp_requests);

		const uint8_t *const p = pkt->get_data();
		const int size = pkt->get_size();

		if (p[6] == 0x00 && p[7] == 0x01 && // request
		    p[2] == 0x08 && p[3] == 0x00 && // ethertype IPv4
		    any_addr(&p[24], 4) == myip) // I am the target?
		{
			stats_inc_counter(arp_for_me);

			uint8_t *reply = duplicate(p, size);

			swap_mac(&reply[8], &reply[18]); // arp addresses

			// my MAC address
			mymac.get(&reply[8], 6);

			reply[7] = 0x02; // reply

			swap_ipv4(&reply[14], &reply[24]);

			if (pdev) {
				pdev->transmit_packet(pkt->get_src_addr(), mymac, 0x0806, reply, size);
			}

			delete [] reply;
		}

		delete pkt;
	}
}

void arp::update_cache(const any_addr & mac, const any_addr & ip)
{
	const std::lock_guard<std::shared_mutex> lock(cache_lock);

	auto it = arp_cache.find(ip);

	if (it == arp_cache.end()) {
		arp_cache.insert({ ip, mac });
		stats_inc_counter(arp_cache_store);
	}
	else {
		it->second = mac;
		stats_inc_counter(arp_cache_update);
	}
}

any_addr * arp::query_cache(const any_addr & ip)
{
	const std::shared_lock<std::shared_mutex> lock(cache_lock);

	stats_inc_counter(arp_cache_req);

	// multicast
	if (ip[0] >= 224 && ip[0] <= 239) {
		stats_inc_counter(arp_cache_hit);

		constexpr uint8_t multicast_mac[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
		return new any_addr(multicast_mac, 6);
	}

	auto it = arp_cache.find(ip);
	if (it == arp_cache.end()) {
		dolog(warning, "ARP: %s is not in the cache\n", ip.to_str().c_str());
		return nullptr;
	}

	stats_inc_counter(arp_cache_hit);

	return new any_addr(it->second);
}

void arp::transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
	// for requests
	assert(0);
}

void arp::transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
	// for requests
	assert(0);
}
