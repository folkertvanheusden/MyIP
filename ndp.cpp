// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <string.h>

#include "ndp.h"
#include "phys.h"
#include "utils.h"

ndp::ndp(stats *const s, const any_addr & mymac, const any_addr & myip6) : address_cache(s, mymac, myip6)
{
	// 1.3.6.1.2.1.4.57850.1.9: ndp
        ndp_cache_req = s->register_stat("ndp_cache_req", "1.3.6.1.2.1.4.57850.1.9.1");
        ndp_cache_hit = s->register_stat("ndp_cache_hit", "1.3.6.1.2.1.4.57850.1.9.2");

	ndp_th = new std::thread(std::ref(*this));
}

ndp::~ndp()
{
	ndp_stop_flag = true;

	ndp_th->join();
	delete ndp_th;
}

void ndp::operator()()
{
	set_thread_name("myip-ndp");

	while(!ndp_stop_flag) {
		std::unique_lock<std::mutex> lck(pkts_lock);

		using namespace std::chrono_literals;

		while(pkts.empty() && !ndp_stop_flag)
			pkts_cv.wait_for(lck, 500ms);

		if (pkts.empty() || ndp_stop_flag)
			continue;

		const packet *pkt = pkts.at(0);
		pkts.erase(pkts.begin());

		lck.unlock();

		// NDP packets are not processed here

		delete pkt;
	}
}

bool ndp::transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
	return false;
}

bool ndp::transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
	return false;
}
