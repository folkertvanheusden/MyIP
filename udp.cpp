// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <chrono>

#include "udp.h"
#include "ipv4.h"
#include "icmp.h"
#include "log.h"
#include "time.h"
#include "utils.h"


udp::udp(stats *const s, icmp *const icmp_) : ip_protocol(s, "udp"), icmp_(icmp_)
{
	udp_requests = s->register_stat("udp_requests");
	udp_refused  = s->register_stat("udp_refused");

	for(int i=0; i<4; i++)
		ths.push_back(new std::thread(std::ref(*this)));
}

udp::~udp()
{
	stop_flag = true;

	for(auto & th : ths) {
		th->join();

		delete th;
	}
}

void udp::operator()()
{
	set_thread_name("myip-udp");

	while(!stop_flag) {
		auto po = pkts->get(500);
		if (!po.has_value())
			continue;

		const packet *pkt = po.value();

		const uint8_t *const p    = pkt->get_data();
		const int            size = pkt->get_size();

		if (size < 8) {
			DOLOG(ll_debug, "UDP: packet too small (%d bytes)\n", size);
			delete pkt;
			continue;
		}

		uint16_t src_port = (p[0] << 8) | p[1];
		uint16_t dst_port = (p[2] << 8) | p[3];

		stats_inc_counter(udp_requests);

		DOLOG(ll_debug, "UDP: packet for port %d from port %d\n", dst_port, src_port);

		cb_lock.lock_shared();
		auto it = callbacks.find(dst_port);

		if (it == callbacks.end()) {
			if (icmp_)
				icmp_->send_destination_port_unreachable(pkt->get_src_addr(), pkt->get_dst_addr(), pkt);

			stats_inc_counter(udp_refused);

			cb_lock.unlock_shared();
		}
		else {
			auto cb = it->second;
			cb_lock.unlock_shared();

			auto src_addr = pkt->get_src_addr();
			auto dst_addr = pkt->get_dst_addr();

			auto header   = pkt->get_header();

			packet *up    = new packet(pkt->get_recv_ts(), pkt->get_src_mac_addr(), src_addr, dst_addr, &p[8], size - 8, header.first, header.second);

			cb.cb(pkt->get_src_addr(), src_port, pkt->get_dst_addr(), dst_port, up, cb.private_data);

			delete up;
		}

		delete pkt;
	}
}

void udp::add_handler(const int port, std::function<void(const any_addr &, int, const any_addr &, int, packet *, session_data *const pd)> h, session_data *pd)
{
	cb_lock.lock();
	callbacks.insert({ port, { h, pd } });
	cb_lock.unlock();
}

void udp::remove_handler(const int port)
{
	cb_lock.lock();
	callbacks.erase(port);
	cb_lock.unlock();
}

bool udp::transmit_packet(const any_addr & dst_ip, const int dst_port, const any_addr & src_ip, const int src_port, const uint8_t *payload, const size_t pl_size)
{
	DOLOG(ll_debug, "UDP: transmit packet %d -> %d\n", src_port, dst_port);

	int out_size = 8 + pl_size;

	uint8_t *out = new uint8_t[out_size + 1]();
	out[0] = src_port >> 8;
	out[1] = src_port;
	out[2] = dst_port >> 8;
	out[3] = dst_port;
	out[4] = out_size >> 8;
	out[5] = out_size;
	out[6] = out[7] = 0;
	memcpy(&out[8], payload, pl_size);

	uint16_t checksum = tcp_udp_checksum(dst_ip, src_ip, false, out, out_size);
	out[6] = checksum >> 8;
	out[7] = checksum;

	out_size += out_size & 1;

	bool rc = false;
	if (idev)
		rc = idev->transmit_packet(dst_ip, src_ip, 0x11, out, out_size, nullptr);

	delete [] out;

	return rc;
}

int udp::allocate_port()
{
	int port = -1;

	ports_lock.lock();

	for(int i=0; i<10; i++) {
		uint16_t rnd;
		get_random((uint8_t *)&rnd, sizeof rnd);

		int test_port = (rnd & 32767) + 1000;

		if (allocated_ports.find(test_port) == allocated_ports.end()) {
			port = test_port;
			allocated_ports.insert({ port, get_us() });
			break;
		}
	}

	ports_lock.unlock();

	return port;
}

void udp::unallocate_port(const int port)
{
	ports_lock.lock();

	allocated_ports.erase(port);

	ports_lock.unlock();
}

void udp::update_port_ts(const int port)
{
	ports_lock.lock();

	auto it = allocated_ports.find(port);

	if (it != allocated_ports.end())
		it->second = get_us();

	ports_lock.unlock();
}
