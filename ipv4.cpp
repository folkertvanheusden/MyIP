// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <stdint.h>
#include <string>
#include <string.h>
#include <arpa/inet.h>

#include "ipv4.h"
#include "arp.h"
#include "phys.h"
#include "icmp.h"
#include "utils.h"

ipv4::ipv4(stats *const s, arp *const iarp, const any_addr & myip) : iarp(iarp), myip(myip)
{
	ip_n_pkt      = s->register_stat("ip_n_pkt", "1.3.6.1.2.1.4.3");
	ip_n_disc     = s->register_stat("ip_n_discards", "1.3.6.1.2.1.4.8");
	ip_n_del      = s->register_stat("ip_n_delivers", "1.3.6.1.2.1.4.9");
	ip_n_out_req  = s->register_stat("ip_n_out_req", "1.3.6.1.2.1.4.10");
	ip_n_out_disc = s->register_stat("ip_n_out_req", "1.3.6.1.2.1.4.11");
	ipv4_n_pkt    = s->register_stat("ipv4_n_pkt");
	ipv4_not_me   = s->register_stat("ipv4_not_me");
	ipv4_ttl_ex   = s->register_stat("ipv4_ttl_ex");
	ipv4_unk_prot = s->register_stat("ipv4_unk_prot");
	ipv4_n_tx     = s->register_stat("ipv4_n_tx");
	ipv4_tx_err   = s->register_stat("ipv4_tx_err");

	assert(myip.get_len() == 4);

	ipv4_th = new std::thread(std::ref(*this));
}

ipv4::~ipv4()
{
	ipv4_stop_flag = true;
	ipv4_th->join();
	delete ipv4_th;
}

void ipv4::transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
	stats_inc_counter(ipv4_n_tx);
	stats_inc_counter(ip_n_out_req);

	if (!pdev) {
		stats_inc_counter(ipv4_tx_err);
		stats_inc_counter(ip_n_out_disc);
		return;
	}

	size_t out_size = 20 + pl_size;
	uint8_t *out = new uint8_t[out_size];

	out[0] = 0x45; // ipv4, 5 words
	out[1] = header_template ? header_template[1] : 0; // qos, ecn
	out[2] = out_size >> 8;
	out[3] = out_size;
	if (header_template) {
		out[4] = header_template[4]; // identification
		out[5] = header_template[5]; // identification
	}
	else {
		out[4] = out[5] = 0; // identification
	}

	dolog(debug, "IPv4[%04x]: transmit packet %s -> %s\n", (out[4] << 8) | out[5], src_ip.to_str().c_str(), dst_ip.to_str().c_str());

	out[6] = out[7] = 0; // flags & fragment offset
	out[8] = header_template ? header_template[8] : 255; // time to live
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
	const any_addr *src_mac = iarp->query_cache(q_addr);
	if (!src_mac) {
		dolog(warning, "IPv4: cannot find src IP (%s) in ARP table\n", q_addr.to_str().c_str());
		delete [] out;
		stats_inc_counter(ipv4_tx_err);
		stats_inc_counter(ip_n_out_disc);
		return;
	}

	pdev->transmit_packet(dst_mac, *src_mac, 0x0800, out, out_size);

	delete src_mac;

	delete [] out;
}

void ipv4::transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
	const any_addr *dst_mac = iarp->query_cache(dst_ip);
	if (!dst_mac) {
		dolog(warning, "IPv4: cannot find dst IP (%s) in ARP table\n", dst_ip.to_str().c_str());
		stats_inc_counter(ipv4_tx_err);
		stats_inc_counter(ip_n_out_disc);
		return;
	}

	transmit_packet(*dst_mac, dst_ip, src_ip, protocol, payload, pl_size, header_template);

	delete dst_mac;
}

void ipv4::operator()()
{
	set_thread_name("myip-ipv4");

	while(!ipv4_stop_flag) {
		std::unique_lock<std::mutex> lck(pkts_lock);

		using namespace std::chrono_literals;

		while(pkts.empty() && !ipv4_stop_flag)
			pkts_cv.wait_for(lck, 500ms);

		if (pkts.empty() || ipv4_stop_flag)
			continue;

		const packet *pkt = pkts.at(0);
		pkts.erase(pkts.begin());

		lck.unlock();

		const uint8_t *const p = pkt->get_data();
		int size = pkt->get_size();

		if (size < 20) {
			dolog(info, "IPv4: not an IPv4 packet (size: %d)\n", size);
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
			dolog(info, "IPv4[%04x]: not an IPv4 packet (version: %d)\n", id, version);
			continue;
		}

		any_addr pkt_dst(&payload_header[16], 4);
		any_addr pkt_src(&payload_header[12], 4);

		// update arp cache
		iarp->update_cache(pkt->get_dst_addr(), pkt_dst);
		iarp->update_cache(pkt->get_src_addr(), pkt_src);

		dolog(debug, "IPv4[%04x]: packet %s => %s\n", id, pkt_src.to_str().c_str(), pkt_dst.to_str().c_str());

		if (pkt_dst != myip) {
			delete pkt;
			stats_inc_counter(ip_n_disc);
			stats_inc_counter(ipv4_not_me);
			continue;
		}

		int header_size = (payload_header[0] & 15) * 4;
		int ip_size = (payload_header[2] << 8) | payload_header[3];
		dolog(debug, "IPv4[%04x]: total packet size: %d, IP header says: %d, header size: %d\n", id, size, ip_size, header_size);

		if (ip_size > size) {
			delete pkt;
			dolog(info, "IPv4[%04x] size (%d) > Ethernet size (%d)\n", id, ip_size, size);
			stats_inc_counter(ip_n_disc);
			continue;
		}

		// adjust size indication to what IP-header says; Ethernet adds padding for small packets (< 60 bytes)
		size = ip_size;

		if (header_size > size) {
			delete pkt;
			dolog(info, "IPv4[%04x] Header size (%d) > size (%d)\n", id, header_size, size);
			stats_inc_counter(ip_n_disc);
			continue;
		}

		const uint8_t *payload_data = &payload_header[header_size];

		const uint8_t protocol = payload_header[9];

		auto it = prot_map.find(protocol);
		if (it == prot_map.end()) {
			delete pkt;
			dolog(info, "IPv4[%04x]: dropping packet %02x (= unknown protocol) and size %d\n", id, protocol, size);
			stats_inc_counter(ipv4_unk_prot);
			stats_inc_counter(ip_n_disc);
			continue;
		}

		int payload_size = size - header_size;

		packet *ip_p = new packet(pkt->get_recv_ts(), pkt->get_src_mac_addr(), pkt_src, pkt_dst, payload_data, payload_size, payload_header, header_size);

		if (payload_header[8] <= 1) { // check TTL
			send_ttl_exceeded(ip_p);
			delete ip_p;
			delete pkt;
			dolog(debug, "IPv4[%04x]: TTL exceeded\n", id);
			stats_inc_counter(ipv4_ttl_ex);
			stats_inc_counter(ip_n_disc);
			continue;
		}

		dolog(debug, "IPv4[%04x]: queing packet protocol %02x and size %d\n", id, protocol, payload_size);

		it->second->queue_packet(ip_p);

		stats_inc_counter(ip_n_del);

		delete pkt;
	}
}

void ipv4::send_ttl_exceeded(const packet *const pkt) const
{
	if (icmp_)
		icmp_->send_packet(pkt->get_src_addr(), pkt->get_dst_addr(), 11, 0, pkt);
}
