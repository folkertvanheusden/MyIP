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

ipv6::ipv6(stats *const s, ndp *const indp, const any_addr & myip) : indp(indp), myip(myip)
{
	ip_n_pkt      = s->register_stat("ip_n_pkt");
	ipv6_n_pkt    = s->register_stat("ipv6_n_pkt");
	ipv6_not_me   = s->register_stat("ipv6_not_me");
	ipv6_ttl_ex   = s->register_stat("ipv6_ttl_ex");
	ipv6_unk_prot = s->register_stat("ipv6_unk_prot");
	ipv6_n_tx     = s->register_stat("ipv6_n_tx");
	ipv6_tx_err   = s->register_stat("ipv6_tx_err");

	assert(myip.get_len() == 16);

	th = new std::thread(std::ref(*this));
}

ipv6::~ipv6()
{
	stop_flag = true;
	th->join();
	delete th;
}

void ipv6::register_protocol(const uint8_t protocol, ip_protocol *const p)
{
	prot_map.insert({ protocol, p });

	p->register_ip(this);
}

void ipv6::transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
	stats_inc_counter(ipv6_n_tx);

	if (!pdev) {
		stats_inc_counter(ipv6_tx_err);
		return;
	}

	size_t out_size = 40 + pl_size;
	uint8_t *out = new uint8_t[out_size];

	out[0] = 0x60;  // IPv6

	uint32_t flow_label = 0;
	get_random((uint8_t *)&flow_label, sizeof flow_label); // FIXME onthouden in een ip/port versus flow_label tabel?
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

        const any_addr *src_mac = indp->query_cache(src_ip);
        if (!src_mac) {
                dolog("IPv6: cannot find src IP (%s) in MAC lookup table\n", src_ip.to_str().c_str());
                delete [] out;
                stats_inc_counter(ipv6_tx_err);
                return;
        }

	pdev->transmit_packet(dst_mac, *src_mac, 0x86dd, out, out_size);

	delete src_mac;

	delete [] out;
}

void ipv6::transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
        const any_addr *dst_mac = indp->query_cache(dst_ip);

        if (dst_mac) {
		transmit_packet(*dst_mac, dst_ip, src_ip, protocol, payload, pl_size, header_template);
		delete dst_mac;
	}
	else {
                dolog("IPv6: cannot find dst IP (%s) in MAC lookup table\n", dst_ip.to_str().c_str());
                stats_inc_counter(ipv6_tx_err);
        }
}

void ipv6::operator()()
{
	set_thread_name("myip-ipv6");

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

		const uint8_t *const p = pkt->get_data();
		int size = pkt->get_size();

		if (size < 40) {
			dolog("IPv6: not an IPv6 packet (size: %d)\n", size);
			delete pkt;
			continue;
		}

		stats_inc_counter(ip_n_pkt);

		const uint8_t *const payload_header = &p[0];

		const uint32_t flow_label = ((payload_header[1] & 15) << 16) | (payload_header[2] << 8) | payload_header[3];

		uint8_t version = payload_header[0] >> 4;
		if (version != 0x06) {
			dolog("IPv6[%04x]: not an IPv6 packet (version: %d)\n", flow_label, version);
			delete pkt;
			continue;
		}

		stats_inc_counter(ipv6_n_pkt);

		any_addr pkt_dst(&payload_header[24], 16);
		any_addr pkt_src(&payload_header[8], 16);

		dolog("IPv6[%04x]: packet %s => %s\n", flow_label, pkt_src.to_str().c_str(), pkt_dst.to_str().c_str());

		bool link_local_scope_multicast_adress = pkt_dst[0] == 0xff && pkt_dst[1] == 0x02;

		if (pkt_dst != myip && !link_local_scope_multicast_adress) {
			dolog("IPv6[%04x]: packet not for me (=%s)\n", flow_label, myip.to_str().c_str());
			delete pkt;
			stats_inc_counter(ipv6_not_me);
			continue;
		}

		indp->update_cache(pkt->get_src_addr(), pkt_src);

		int ip_size = (payload_header[4] << 8) | payload_header[5];

		if (ip_size > size) {
			dolog("IPv6[%04x]: packet is bigger on the inside (%d) than on the outside (%d)\n", flow_label, ip_size, size);
			ip_size = size;
		}

		uint8_t protocol = payload_header[6];
		const uint8_t *nh = &payload_header[40], *const eh = &payload_header[size - ip_size];
		
		while(eh - nh >= 8) {
			// FIXME send "icmp6 Parameter Problem" for each unrecognized/unprocessed "next header"

			protocol = nh[0];
			nh += (nh[1] + 1) * 8;
		}

		int header_size = nh - payload_header;

		dolog("IPv6[%04x]: total packet size: %d, IP header says: %d, header size: %d\n", flow_label, size, ip_size, header_size);

		if (ip_size > size) {
			dolog("IPv6[%04x] size (%d) > Ethernet size (%d)\n", flow_label, ip_size, size);
			delete pkt;
			continue;
		}

		// adjust size indication to what IP-header says; Ethernet adds padding for small packets (< 60 bytes)
		size = ip_size;

		const uint8_t *payload_data = &payload_header[header_size];

		int payload_size = size;

		auto it = prot_map.find(protocol);
		if (it == prot_map.end()) {
			dolog("IPv6[%04x]: dropping packet %02x (= unknown protocol) and size %d\n", flow_label, protocol, size);
			stats_inc_counter(ipv6_unk_prot);
			delete pkt;
			continue;
		}

		dolog("IPv6[%04x]: queing packet protocol %02x and size %d\n", flow_label, protocol, payload_size);

		packet *ip_p = new packet(pkt->get_recv_ts(), pkt->get_src_mac_addr(), pkt_src, pkt_dst, payload_data, payload_size, payload_header, header_size);

		it->second->queue_packet(ip_p);

		delete pkt;
	}
}
