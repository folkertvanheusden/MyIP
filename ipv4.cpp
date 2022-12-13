// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <stdint.h>
#include <string>
#include <string.h>
#include <arpa/inet.h>

#include "arp.h"
#include "icmp.h"
#include "ipv4.h"
#include "log.h"
#include "phys.h"
#include "router.h"
#include "utils.h"


ipv4::ipv4(stats *const s, arp *const iarp, const any_addr & myip, router *const r, const bool forward, const int n_threads) : network_layer(s, "ipv4", r), iarp(iarp), myip(myip), forward(forward)
{
	ip_n_pkt      = s->register_stat("ip_n_pkt",      "1.3.6.1.2.1.4.3");
	ip_n_disc     = s->register_stat("ip_n_discards", "1.3.6.1.2.1.4.8");
	ip_n_del      = s->register_stat("ip_n_delivers", "1.3.6.1.2.1.4.9");
	ip_n_out_req  = s->register_stat("ip_n_out_req",  "1.3.6.1.2.1.4.10");
	ip_n_out_disc = s->register_stat("ip_n_out_req",  "1.3.6.1.2.1.4.11");
	ipv4_n_pkt    = s->register_stat("ipv4_n_pkt");
	ipv4_not_me   = s->register_stat("ipv4_not_me");
	ipv4_ttl_ex   = s->register_stat("ipv4_ttl_ex");
	ipv4_unk_prot = s->register_stat("ipv4_unk_prot");
	ipv4_n_tx     = s->register_stat("ipv4_n_tx");
	ipv4_tx_err   = s->register_stat("ipv4_tx_err");

	assert(myip.get_family() == any_addr::ipv4);

	for(int i=0; i<n_threads; i++)
		ths.push_back(new std::thread(std::ref(*this)));
}

ipv4::~ipv4()
{
	stop_flag = true;

	for(auto & th : ths) {
		th->join();

		delete th;
	}
}

bool ipv4::transmit_packet(const std::optional<any_addr> & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
	assert(dst_ip.get_family() == any_addr::ipv4);
	assert(src_ip.get_family() == any_addr::ipv4);

	stats_inc_counter(ipv4_n_tx);
	stats_inc_counter(ip_n_out_req);

	size_t out_size = 20 + pl_size;
	uint8_t *out = new uint8_t[out_size];

	out[0] = 0x45; // ipv4, 5 words
	out[1] = header_template ? header_template[1] : 0; // qos, ecn
	out[2] = out_size >> 8;
	out[3] = out_size;

	out[4] = out[5] = 0; // identification

	DOLOG(ll_debug, "IPv4[%04x]: transmit packet %s -> %s\n", (out[4] << 8) | out[5], src_ip.to_str().c_str(), dst_ip.to_str().c_str());

	out[6] = 0x40;
	out[7] = 0; // flags (DF) & fragment offset
	out[8] = 64; // time to live
	out[9] = protocol;
	out[10] = out[11] = 0; // checksum

	bool override_ip = !src_ip.is_set();

	// source IPv4 address
	(override_ip ? myip : src_ip).get(&out[12], 4);

	// destination IPv4 address
	dst_ip.get(&out[16], 4);

	memcpy(&out[20], payload, pl_size);

	uint16_t checksum = ip_checksum((const uint16_t *)&out[0], 10);
	out[10] = checksum >> 8;
	out[11] = checksum;

	any_addr q_addr = override_ip ? myip : src_ip;

	auto src_mac = iarp->query_cache(q_addr);

	bool rc = r->route_packet(dst_mac, 0x0800, dst_ip, *src_mac.second, q_addr, out, out_size);

	delete src_mac.second;

	delete [] out;

	return rc;
}

void ipv4::operator()()
{
	set_thread_name("myip-ipv4");

	while(!stop_flag) {
		auto po = pkts->get(500);
		if (!po.has_value())
			continue;

		const packet *pkt = po.value().p;

		const uint8_t *const p = pkt->get_data();
		int size = pkt->get_size();

		if (size < 20) {
			DOLOG(ll_info, "IPv4: not an IPv4 packet (size: %d)\n", size);
			delete pkt;
			continue;
		}

		// assuming link layer takes care of corruptions so no checksum verification

		stats_inc_counter(ip_n_pkt);

		const uint8_t *const payload_header = &p[0];

		const uint16_t id = (payload_header[4] << 8) | payload_header[5];

		stats_inc_counter(ipv4_n_pkt);

		uint8_t version = payload_header[0] >> 4;
		if (version != 0x04) {
			delete pkt;
			stats_inc_counter(ip_n_disc);
			DOLOG(ll_info, "IPv4[%04x]: not an IPv4 packet (version: %d)\n", id, version);
			continue;
		}

		any_addr pkt_dst(any_addr::ipv4, &payload_header[16]);
		any_addr pkt_src(any_addr::ipv4, &payload_header[12]);

		iarp->update_cache(pkt->get_src_addr(), pkt_src, po.value().interface);

		DOLOG(ll_debug, "IPv4[%04x]: packet %s => %s\n", id, pkt_src.to_str().c_str(), pkt_dst.to_str().c_str());

		int header_size = (payload_header[0] & 15) * 4;
		int ip_size     = (payload_header[2] << 8) | payload_header[3];
		DOLOG(ll_debug, "IPv4[%04x]: total packet size: %d, IP header says: %d, header size: %d\n", id, size, ip_size, header_size);

		if (ip_size > size) {
			delete pkt;
			DOLOG(ll_info, "IPv4[%04x] size (%d) > Ethernet size (%d)\n", id, ip_size, size);
			stats_inc_counter(ip_n_disc);
			continue;
		}

		// adjust size indication to what IP-header says; Ethernet adds padding for small packets (< 60 bytes)
		size = ip_size;

		if (header_size > size) {
			delete pkt;
			DOLOG(ll_info, "IPv4[%04x] Header size (%d) > size (%d)\n", id, header_size, size);
			stats_inc_counter(ip_n_disc);
			continue;
		}

		const uint8_t *payload_data = &payload_header[header_size];

		const uint8_t protocol = payload_header[9];

		auto it = prot_map.find(protocol);
		if (it == prot_map.end()) {
			delete pkt;
			DOLOG(ll_debug, "IPv4[%04x]: dropping packet %02x (= unknown protocol) and size %d\n", id, protocol, size);
			stats_inc_counter(ipv4_unk_prot);
			stats_inc_counter(ip_n_disc);
			continue;
		}

		int payload_size = size - header_size;

		if (pkt_dst != myip) {
			if (forward) {
				DOLOG(ll_debug, "IPv4[%04x]: forwarding packet to router\n", id);

				r->route_packet({ }, 0x0800, pkt_dst, pkt->get_src_mac_addr(), pkt_src, payload_data, payload_size);
			}
			else {
				DOLOG(ll_debug, "IPv4[%04x]: dropping packet\n", id);

				stats_inc_counter(ip_n_disc);
			}

			stats_inc_counter(ipv4_not_me);

			delete pkt;

			continue;
		}

		packet *ip_p = new packet(pkt->get_recv_ts(), pkt->get_src_mac_addr(), pkt_src, pkt_dst, payload_data, payload_size, payload_header, header_size);

		if (payload_header[8] <= 1) { // check TTL
			send_ttl_exceeded(ip_p);
			delete ip_p;
			delete pkt;
			DOLOG(ll_debug, "IPv4[%04x]: TTL exceeded\n", id);
			stats_inc_counter(ipv4_ttl_ex);
			stats_inc_counter(ip_n_disc);
			continue;
		}

		DOLOG(ll_debug, "IPv4[%04x]: queing packet protocol %02x and size %d\n", id, protocol, payload_size);

		it->second->queue_packet(ip_p);

		stats_inc_counter(ip_n_del);

		delete pkt;
	}
}

void ipv4::send_ttl_exceeded(const packet *const pkt) const
{
	if (icmp_)
		icmp_->send_ttl_exceeded(pkt);
}
