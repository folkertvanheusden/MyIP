// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <string.h>

#include "arp.h"
#include "log.h"
#include "net.h"
#include "phys.h"
#include "router.h"
#include "time.h"
#include "utils.h"


using namespace std::chrono_literals;

constexpr size_t pkts_max_size { 256 };

arp::arp(stats *const s, phys *const interface, const any_addr & my_mac, const any_addr & my_ip, const any_addr & gw_mac) :
	address_cache(s),
	mac_resolver(s, nullptr),
	gw_mac(gw_mac), my_mac(my_mac), my_ip(my_ip),
	interface(interface)
{
	// 1.3.6.1.2.1.4.57850.1.11: arp
	arp_requests     = s->register_stat("arp_requests", "1.3.6.1.2.1.4.57850.1.11.1");
	arp_for_me       = s->register_stat("arp_for_me",   "1.3.6.1.2.1.4.57850.1.11.2");

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
		auto po = pkts->get(500);
		if (!po.has_value())
			continue;

		const packet *pkt = po.value().p;

		stats_inc_counter(arp_requests);

		const uint8_t *const p = pkt->get_data();
		const int size = pkt->get_size();

		if (p[6] == 0x00 && p[7] == 0x01 &&  // request
		    p[2] == 0x08 && p[3] == 0x00 &&  // ethertype IPv4
		    any_addr(any_addr::ipv4, &p[24]) == my_ip)  // am I the target?
		{
			stats_inc_counter(arp_for_me);

			uint8_t *reply = duplicate(p, size);

			swap_mac(&reply[8], &reply[18]); // arp addresses

			// my MAC address
			my_mac.get(&reply[8], 6);

			reply[7] = 0x02; // reply

			swap_ipv4(&reply[14], &reply[24]);

			po.value().interface->transmit_packet(pkt->get_src_addr(), my_mac, 0x0806, reply, size);

			delete [] reply;
		}
		else if (p[6] == 0x00 && p[7] == 0x02 &&  // reply
			any_addr(any_addr::mac, &p[8]) == my_mac) {  // check sender

			std::unique_lock lck(work_lock);

			auto it = work.find(any_addr(any_addr::ipv4, &p[24]));  // IP to resolve

			if (it != work.end())
				it->second = mac_resolver_result({ any_addr(any_addr::ipv4, &p[18]) });

			work_cv.notify_all();
		}
		else {
			// DOLOG(ll_debug, "ARP: not for me? request %02x%02x, ethertype %02x%02x target %s\n", p[6], p[7], p[2], p[3], any_addr(&p[24], 4).to_str().c_str());
		}

		delete pkt;
	}
}

bool arp::send_request(const any_addr & ip)
{
	uint8_t request[26] { 0 };

	request[1] = 1;  // HTYPE (Ethernet)

	// PTYPE
	if (ip.get_len() == 4)
		request[2] = 0x08, request[3] = 0x00;
	else {
		DOLOG(ll_warning, "ARP::send_request: don't know how to resolve \"%s\" with ARP", ip.to_str().c_str());
		return false;
	}

	request[4] = 6;  // HLEN
	request[5] = ip.get_len();  // PLEN

	request[6] = 0x00;  // OPER
	request[7] = 1;

	my_mac.get(&request[8], 6);  // SHA

	ip.get(&request[14], 4);  // SPA

	constexpr const uint8_t broadcast_mac[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	any_addr dest_mac(any_addr::mac, broadcast_mac);

	return interface->transmit_packet(dest_mac, my_mac, 0x0806, request, sizeof request);
}

std::optional<any_addr> arp::get_mac(const any_addr & ip)
{
	assert(ip.get_family() == any_addr::ipv4 || ip.get_family() == any_addr::ipv6);

	auto cache_result = query_cache(ip);

	if (cache_result.first == interface) {
		any_addr rc = *cache_result.second;

		delete cache_result.second;

		return rc;
	}

	if (!send_request(ip))
		return { };

	uint32_t start_ts = get_ms();

	std::unique_lock lck(work_lock);

	for(;!stop_flag && get_ms() - start_ts < 1000;) {
		auto it = work.find(ip);

		if (it == work.end()) {  // should not happen
			DOLOG(ll_warning, "ARP: nothing queued for %s", ip.to_str().c_str());

			return { };
		}

		if (it->second.has_value()) {
			auto result = it->second.value().mac;

			work.erase(it);

			if (result.has_value())
				update_cache(result.value(), ip, interface);

			return result;
		}

		work_cv.wait_for(lck, 100ms);
	}

	DOLOG(ll_debug, "ARP: resolve for %s timeout\n", ip.to_str().c_str());

	return { };
}
