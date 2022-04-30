// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <stdint.h>
#include <string>
#include <string.h>
#include <arpa/inet.h>

#include "ipv6.h"
#include "phys.h"
#include "icmp.h"
#include "utils.h"

ipv6::ipv6(stats *const s, ndp *const indp, const any_addr & myip) : protocol(s, "ipv6"), indp(indp), myip(myip)
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

	assert(myip.get_len() == 16);

	for(int i=0; i<4; i++)
		ths.push_back(new std::thread(std::ref(*this)));
}

ipv6::~ipv6()
{
	stop_flag = true;

	for(auto & th : ths) {
		th->join();

		delete th;
	}
}

bool ipv6::transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
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

	auto ndp_result = indp->query_cache(src_ip);
        const any_addr *src_mac = ndp_result.second;
        if (!src_mac) {
                DOLOG(warning, "IPv6: cannot find src IP (%s) in MAC lookup table\n", src_ip.to_str().c_str());
                delete [] out;
                stats_inc_counter(ipv6_tx_err);
		stats_inc_counter(ip_n_out_disc);
                return false;
        }

	bool rc = ndp_result.first->transmit_packet(dst_mac, *src_mac, 0x86dd, out, out_size);

	delete src_mac;

	delete [] out;

	return rc;
}

bool ipv6::transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
	bool rc = false;

	auto ndp_result = indp->query_cache(dst_ip);
        const any_addr *dst_mac = ndp_result.second;

        if (dst_mac) {
		rc = transmit_packet(*dst_mac, dst_ip, src_ip, protocol, payload, pl_size, header_template);
		delete dst_mac;
	}
	else {
                DOLOG(warning, "IPv6: cannot find dst IP (%s) in MAC lookup table\n", dst_ip.to_str().c_str());
		stats_inc_counter(ip_n_out_disc);
                stats_inc_counter(ipv6_tx_err);
        }

	return rc;
}

void ipv6::operator()()
{
	set_thread_name("myip-ipv6");

	while(!stop_flag) {
		auto po = pkts->get(500);
		if (!po.has_value())
			continue;

		const packet *pkt = po.value().p;

		stats_inc_counter(ip_n_pkt);

		const uint8_t *const p = pkt->get_data();
		int size = pkt->get_size();

		if (size < 40) {
			DOLOG(info, "IPv6: not an IPv6 packet (size: %d)\n", size);
			stats_inc_counter(ip_n_disc);
			delete pkt;
			continue;
		}

		const uint8_t *const payload_header = &p[0];

		const uint32_t flow_label = ((payload_header[1] & 15) << 16) | (payload_header[2] << 8) | payload_header[3];

		uint8_t version = payload_header[0] >> 4;
		if (version != 0x06) {
			DOLOG(info, "IPv6[%04x]: not an IPv6 packet (version: %d)\n", flow_label, version);
			stats_inc_counter(ip_n_disc);
			delete pkt;
			continue;
		}

		stats_inc_counter(ipv6_n_pkt);

		any_addr pkt_dst(&payload_header[24], 16);
		any_addr pkt_src(&payload_header[8], 16);

		DOLOG(debug, "IPv6[%04x]: packet %s => %s\n", flow_label, pkt_src.to_str().c_str(), pkt_dst.to_str().c_str());

		bool link_local_scope_multicast_adress = pkt_dst[0] == 0xff && pkt_dst[1] == 0x02;

		if (pkt_dst != myip && !link_local_scope_multicast_adress) {
			DOLOG(info, "IPv6[%04x]: packet not for me (=%s)\n", flow_label, myip.to_str().c_str());
			delete pkt;
			stats_inc_counter(ipv6_not_me);
			stats_inc_counter(ip_n_disc);
			continue;
		}

		indp->update_cache(pkt->get_src_addr(), pkt_src, po.value().interface);

		int ip_size = (payload_header[4] << 8) | payload_header[5];

		if (ip_size > size) {
			DOLOG(info, "IPv6[%04x]: packet is bigger on the inside (%d) than on the outside (%d)\n", flow_label, ip_size, size);
			ip_size = size;
		}

		uint8_t protocol = payload_header[6];
		const uint8_t *nh = &payload_header[40], *const eh = &payload_header[size - ip_size];
		
		while(eh - nh >= 8) {
			protocol = nh[0];
			nh += (nh[1] + 1) * 8;
		}

		int header_size = nh - payload_header;

		DOLOG(debug, "IPv6[%04x]: total packet size: %d, IP header says: %d, header size: %d\n", flow_label, size, ip_size, header_size);

		if (ip_size > size) {
			DOLOG(info, "IPv6[%04x] size (%d) > Ethernet size (%d)\n", flow_label, ip_size, size);
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
			DOLOG(debug, "IPv6[%04x]: dropping packet %02x (= unknown protocol) and size %d\n", flow_label, protocol, size);
			delete pkt;
			stats_inc_counter(ipv6_unk_prot);
			stats_inc_counter(ip_n_disc);
			continue;
		}

		DOLOG(debug, "IPv6[%04x]: queing packet protocol %02x and size %d\n", flow_label, protocol, payload_size);

		packet *ip_p = new packet(pkt->get_recv_ts(), pkt->get_src_mac_addr(), pkt_src, pkt_dst, payload_data, payload_size, payload_header, header_size);

		it->second->queue_packet(ip_p);

		stats_inc_counter(ip_n_del);

		delete pkt;
	}
}
