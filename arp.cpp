// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under AGPL v3.0
#include <chrono>
#include <string.h>

#include "arp.h"
#include "phys.h"
#include "utils.h"

arp::arp(stats *const s, const uint8_t mymac[6], const uint8_t myip[4])
{
	arp_requests  = s->register_stat("arp_requests");
	arp_for_me    = s->register_stat("arp_for_me");
	arp_cache_req = s->register_stat("arp_cache_req");
	arp_cache_hit = s->register_stat("arp_cache_hit");

	memcpy(this->mymac, mymac, sizeof(this->mymac));
	memcpy(this->myip, myip, sizeof(this->myip));

	update_cache(mymac, myip);

	th = new std::thread(std::ref(*this));
}

arp::~arp()
{
	for(auto it : arp_cache)
		delete [] it.second;

	stop_flag = true;
	th->join();
	delete th;
}

void arp::operator()()
{
	set_thread_name("arp");

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
		    memcmp(&p[24], myip, sizeof(myip)) == 0) // I am the target?
		{
			stats_inc_counter(arp_for_me);

			uint8_t *reply = duplicate(p, size);

			swap_mac(&reply[8], &reply[18]); // arp addresses
			memcpy(&reply[8], mymac, 6); // my mac

			reply[7] = 0x02; // reply

			swap_ipv4(&reply[14], &reply[24]);

			if (pdev)
				pdev->transmit_packet(pkt->get_src_addr().first, mymac, 0x0806, reply, size);

			delete [] reply;
		}

		delete pkt;
	}
}

void arp::update_cache(const uint8_t *const mac, const uint8_t *const ip)
{
	const std::lock_guard<std::shared_mutex> lock(cache_lock);

	uint32_t ip_word = (ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3];

	auto it = arp_cache.find(ip_word);
	if (it == arp_cache.end()) {
		uint8_t *mac_copy = duplicate(mac, 6);

		arp_cache.insert({ ip_word, mac_copy });
	}
	else {
		memcpy(it->second, mac, 6);
	}
}

uint8_t * arp::query_cache(const uint8_t *const ip)
{
	const std::shared_lock<std::shared_mutex> lock(cache_lock);

	stats_inc_counter(arp_cache_req);

	// multicast
	if (ip[0] >= 224 && ip[0] <= 239) {
		stats_inc_counter(arp_cache_hit);

		constexpr uint8_t multicast_mac[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
		return duplicate(multicast_mac, 6);
	}

	uint32_t ip_word = (ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3];

	auto it = arp_cache.find(ip_word);
	if (it == arp_cache.end()) {
		dolog("ARP: %d.%d.%d.%d is not in the cache\n", ip[0], ip[1], ip[2], ip[3]);
		return nullptr;
	}

	stats_inc_counter(arp_cache_hit);

	return duplicate(it->second, 6);
}
