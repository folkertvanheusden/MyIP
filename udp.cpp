// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <chrono>

#include "udp.h"
#include "ipv4.h"
#include "icmp.h"
#include "utils.h"

udp::udp(stats *const s, icmp *const icmp_) : icmp_(icmp_)
{
	udp_requests = s->register_stat("udp_requests");
	udp_refused = s->register_stat("udp_refused");

	th = new std::thread(std::ref(*this));
}

udp::~udp()
{
	for(auto p : pkts)
		delete p;

	stop_flag = true;
	th->join();
	delete th;
}

void udp::operator()()
{
	set_thread_name("myip-udp");

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
		const int size = pkt->get_size();

		uint16_t src_port = (p[0] << 8) | p[1];
		uint16_t dst_port = (p[2] << 8) | p[3];

		stats_inc_counter(udp_requests);

		dolog(debug, "UDP: packet for port %d from port %d\n", dst_port, src_port);

		auto it = callbacks.find(dst_port);

		if (it == callbacks.end()) {
			if (icmp_)
				icmp_->send_packet(pkt->get_src_addr(), pkt->get_dst_addr(), 3, 3, pkt);

			stats_inc_counter(udp_refused);
		}
		else {
			auto src_addr = pkt->get_src_addr();
			auto dst_addr = pkt->get_dst_addr();

			auto header = pkt->get_header();

			packet *up = new packet(pkt->get_recv_ts(), pkt->get_src_mac_addr(), src_addr, dst_addr, &p[8], size - 8, header.first, header.second);

			it->second(pkt->get_src_addr(), src_port, pkt->get_dst_addr(), dst_port, up);

			delete up;
		}

		delete pkt;
	}
}

void udp::add_handler(const int port, std::function<void(const any_addr &, int, const any_addr &, int, packet *)> h)
{
	callbacks.insert({ port, h });
}

void udp::transmit_packet(const any_addr & dst_ip, const int dst_port, const any_addr & src_ip, const int src_port, const uint8_t *payload, const size_t pl_size)
{
	dolog(debug, "UDP: transmit packet %d -> %d\n", src_port, dst_port);

	int out_size = 8 + pl_size;
	out_size += out_size & 1;

	uint8_t *out = new uint8_t[out_size]();
	out[0] = src_port >> 8;
	out[1] = src_port;
	out[2] = dst_port >> 8;
	out[3] = dst_port;
	out[4] = out_size >> 8;
	out[5] = out_size;
	out[6] = out[7] = 0;
	memcpy(&out[8], payload, pl_size);

	uint16_t checksum = ipv4_checksum((const uint16_t *)&out[0], out_size / 2);
	out[10] = checksum >> 8;
	out[11] = checksum;

	if (idev)
		idev->transmit_packet(dst_ip, src_ip, 0x11, out, out_size, nullptr);

	delete [] out;
}
