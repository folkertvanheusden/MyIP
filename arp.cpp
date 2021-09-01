// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <string.h>

#include "arp.h"
#include "phys.h"
#include "utils.h"

arp::arp(stats *const s, const any_addr & mymac, const any_addr & myip) : address_cache(s, mymac, myip)
{
	arp_requests     = s->register_stat("arp_requests");
	arp_for_me       = s->register_stat("arp_for_me");

	arp_th = new std::thread(std::ref(*this));
}

arp::~arp()
{
	arp_stop_flag = true;
	arp_th->join();
	delete arp_th;
}

void arp::operator()()
{
	set_thread_name("myip-arp");

	while(!arp_stop_flag) {
		std::unique_lock<std::mutex> lck(pkts_lock);

		using namespace std::chrono_literals;

		while(pkts.empty() && !arp_stop_flag)
			pkts_cv.wait_for(lck, 500ms);

		if (pkts.empty() || arp_stop_flag)
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
		else {
			dolog(debug, "ARP: not for me? request %02x%02x, ethertype %02x%02x target %s\n", p[6], p[7], p[2], p[3], any_addr(&p[24], 4).to_str().c_str());
		}

		delete pkt;
	}
}

any_addr * arp::query_cache(const any_addr & ip)
{
	assert(ip.get_len() == 4);

	// multicast
	if (ip[0] >= 224 && ip[0] <= 239) {
		stats_inc_counter(address_cache_hit);

		constexpr uint8_t multicast_mac[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
		return new any_addr(multicast_mac, 6);
	}

	return address_cache::query_cache(ip);
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
