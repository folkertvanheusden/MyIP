// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <optional>
#include <stdint.h>
#include <string>
#include <string.h>
#include <arpa/inet.h>

#include "icmp.h"
#include "ipv6.h"
#include "log.h"
#include "phys.h"
#include "router.h"
#include "str.h"
#include "utils.h"


ipv6::ipv6(stats *const s, ndp *const indp, const any_addr & myip, router *const r, const int n_threads) : network_layer(s, "ipv6", r), indp(indp), myip(myip)
{
	ip_n_pkt      = s->register_stat("ip_n_pkt", "1.3.6.1.2.1.4.3");
	ip_n_disc     = s->register_stat("ip_n_discards", "1.3.6.1.2.1.4.8");
	ip_n_del      = s->register_stat("ip_n_delivers", "1.3.6.1.2.1.4.9");
	ip_n_out_req  = s->register_stat("ip_n_out_req", "1.3.6.1.2.1.4.10");
	ip_n_out_disc = s->register_stat("ip_n_out_req", "1.3.6.1.2.1.4.11");
	ipv6_n_pkt    = s->register_stat("ipv6_n_pkt");
	ipv6_not_me   = s->register_stat("ipv6_not_me");
	ipv6_ttl_ex   = s->register_stat("ipv6_ttl_ex");
	ipv6_unk_prot = s->register_stat("ipv6_unk_prot");
	ipv6_n_tx     = s->register_stat("ipv6_n_tx");
	ipv6_tx_err   = s->register_stat("ipv6_tx_err");

	assert(myip.get_family() == any_addr::ipv6);

	for(int i=0; i<n_threads; i++)
		ths.push_back(new std::thread(std::ref(*this)));
}

ipv6::~ipv6()
{
	for(auto & th : ths) {
		th->join();

		delete th;
	}
}

bool ipv6::transmit_packet(const std::optional<any_addr> & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
	stats_inc_counter(ipv6_n_tx);
	stats_inc_counter(ip_n_out_req);

	size_t out_size = 40 + pl_size;
	uint8_t *out = new uint8_t[out_size];

	out[0] = 0x60;  // IPv6

	// not sure if this should be stored per session
	uint32_t flow_label = 0;
	get_random((uint8_t *)&flow_label, sizeof flow_label);
	out[1] = (flow_label >> 16) & 0x0f;
	out[2] = flow_label >> 8;
	out[3] = flow_label;

	out[4] = pl_size >> 8;
	out[5] = pl_size;

	out[6] = protocol;
	out[7] = 255;  // basically ignored according to wikipedia?

	src_ip.get(&out[8], 16);

	dst_ip.get(&out[24], 16);

	if (pl_size)
		memcpy(&out[40], payload, pl_size);

	auto src_mac = indp->query_cache(src_ip);

	bool rc = r->route_packet(dst_mac, 0x86dd, dst_ip, *src_mac.second, src_ip, out, out_size);

	delete src_mac.second;

	delete [] out;

	return rc;
}

void ipv6::operator()()
{
	set_thread_name("myip-ipv6");

	for(;;) {
		auto po = pkts->get();
		if (!po.has_value())
			break;

		packet *pkt = po.value().p;

		stats_inc_counter(ip_n_pkt);

		const uint8_t *const p = pkt->get_data();
		int size = pkt->get_size();

		if (size < 40) {
			DOLOG(ll_info, "IPv6: not an IPv6 packet (size: %d)\n", size);
			stats_inc_counter(ip_n_disc);
			delete pkt;
			continue;
		}

		const uint8_t *const payload_header = &p[0];

		const uint32_t flow_label = ((payload_header[1] & 15) << 16) | (payload_header[2] << 8) | payload_header[3];

		uint8_t version = payload_header[0] >> 4;
		if (version != 0x06) {
			DOLOG(ll_info, "%s: not an IPv6 packet (version: %d)\n", pkt->get_log_prefix().c_str(), version);
			stats_inc_counter(ip_n_disc);
			delete pkt;
			continue;
		}

		stats_inc_counter(ipv6_n_pkt);

		any_addr pkt_dst(any_addr::ipv6, &payload_header[24]);
		any_addr pkt_src(any_addr::ipv6, &payload_header[8]);

		pkt->add_to_log_prefix(myformat("IPv6[%s]", pkt_src.to_str().c_str()));

		DOLOG(ll_debug, "%s: packet %s => %s\n", pkt->get_log_prefix().c_str(), pkt_src.to_str().c_str(), pkt_dst.to_str().c_str());

		bool link_local_scope_multicast_adress = pkt_dst[0] == 0xff && pkt_dst[1] == 0x02;

		if (pkt_dst != myip && !link_local_scope_multicast_adress) {
			DOLOG(ll_debug, "%s: packet (%s) not for me (=%s)\n", pkt->get_log_prefix().c_str(), pkt_src.to_str().c_str(), myip.to_str().c_str());
			delete pkt;
			stats_inc_counter(ipv6_not_me);
			stats_inc_counter(ip_n_disc);
			continue;
		}

		indp->update_cache(pkt->get_src_addr(), pkt_src, po.value().interface);

		int ip_size = (payload_header[4] << 8) | payload_header[5];

		if (ip_size > size) {
			DOLOG(ll_info, "%s: packet is bigger on the inside (%d) than on the outside (%d)\n", pkt->get_log_prefix().c_str(), ip_size, size);
			ip_size = size;
		}

		uint8_t protocol = payload_header[6];
		const uint8_t *nh = &payload_header[40], *const eh = &payload_header[size - ip_size];
		
		while(eh - nh >= 8) {
			protocol = nh[0];
			nh += (nh[1] + 1) * 8;
		}

		int header_size = nh - payload_header;

		DOLOG(ll_debug, "%s: total packet size: %d, IP header says: %d, header size: %d\n", pkt->get_log_prefix().c_str(), size, ip_size, header_size);

		if (ip_size > size) {
			DOLOG(ll_info, "%s size (%d) > Ethernet size (%d)\n", pkt->get_log_prefix().c_str(), ip_size, size);
			delete pkt;
			stats_inc_counter(ip_n_disc);
			continue;
		}

		// adjust size indication to what IP-header says; Ethernet adds padding for small packets (< 60 bytes)
		size = ip_size;

		const uint8_t *payload_data = &payload_header[header_size];

		int payload_size = size;

		auto it = prot_map.find(protocol);
		if (it == prot_map.end()) {
			DOLOG(ll_debug, "%s: dropping packet %02x (= unknown protocol) and size %d\n", pkt->get_log_prefix().c_str(), protocol, size);
			delete pkt;
			stats_inc_counter(ipv6_unk_prot);
			stats_inc_counter(ip_n_disc);
			continue;
		}

		DOLOG(ll_debug, "%s: queing packet protocol %02x and size %d\n", pkt->get_log_prefix().c_str(), protocol, payload_size);

		packet *ip_p = new packet(pkt->get_recv_ts(), pkt->get_src_mac_addr(), pkt_src, pkt_dst, payload_data, payload_size, payload_header, header_size, pkt->get_log_prefix());

		it->second->queue_packet(ip_p);

		stats_inc_counter(ip_n_del);

		delete pkt;
	}
}
