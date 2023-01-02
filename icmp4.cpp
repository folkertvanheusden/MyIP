// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <chrono>

#include "icmp4.h"
#include "ipv4.h"
#include "log.h"
#include "time.h"
#include "utils.h"


icmp4::icmp4(stats *const s, const int n_threads) : icmp(s)
{
	icmp_requests = s->register_stat("icmp_requests");
	icmp_req_ping = s->register_stat("icmp_req_ping");
	icmp_transmit = s->register_stat("icmp_transmit");

	for(int i=0; i<n_threads; i++)
		ths.push_back(new std::thread(std::ref(*this)));
}

icmp4::~icmp4()
{
	stop_flag = true;

	for(auto & th : ths) {
		th->join();

		delete th;
	}
}

void icmp4::operator()()
{
	set_thread_name("myip-icmp4");

	while(!stop_flag) {
		auto po = pkts->get(500);
		if (!po.has_value())
			continue;

		const packet *pkt = po.value();

		const uint8_t *const p = pkt->get_data();
		const int size = pkt->get_size();

		if (size < 8) {
			DOLOG(ll_debug, "ICMP: not a valid packet (too small (%d bytes))\n", size);
			delete pkt;
			continue;
		}

		stats_inc_counter(icmp_requests);

		const any_addr src_ip = pkt->get_src_addr();
		DOLOG(ll_debug, "ICMP: request by %s\n", src_ip.to_str().c_str());

		uint8_t *reply = duplicate(p, size);

		if (p[0] == 8) {  // echo request
			stats_inc_counter(icmp_req_ping);

			reply[0] = 0; // echo reply
		}
		else if (p[0] == 13 && size >= 20) {  // timestamp request
			reply[0] = 14; // timestamp reply

			uint32_t reply_ts = ms_since_midnight();

			reply[12] = reply[16] = reply_ts >> 24;
			reply[13] = reply[17] = reply_ts >> 16;
			reply[14] = reply[18] = reply_ts >>  8;
			reply[15] = reply[19] = reply_ts;
		}
		else {
			DOLOG(ll_debug, "ICMP: dropping packet (type %d code %d)\n", p[0], p[1]);
			delete pkt;
			continue;
		}

		if (idev) {
			auto     header      = pkt->get_header();
			uint8_t *header_copy = duplicate(header.first, header.second);

			uint16_t identification = ((header_copy[4] << 8) | header_copy[5]) + 1;

			header_copy[4] = identification >> 8;
			header_copy[5] = identification;

			reply[2] = reply[3] = 0;
			uint16_t checksum = ip_checksum(reinterpret_cast<const uint16_t *>(reply), size / 2);
			reply[2] = checksum >> 8;
			reply[3] = checksum;

			timespec now_ts { 0, 0 };

			if (clock_gettime(CLOCK_REALTIME, &now_ts) == -1)
				DOLOG(ll_warning, "clock_gettime failed: %s", strerror(errno));
			else {
				timespec in_ts = pkt->get_recv_ts();
				timespec diff { 0, 0 };
				timespecsub(&now_ts, &in_ts, &diff);

				int32_t tdiff = diff.tv_sec * 1000000 + diff.tv_nsec / 1000;

				DOLOG(ll_debug, "ICMP: sending response after %dus\n", tdiff);
			}

			// this is the correct order! sending a reply!
			idev->transmit_packet({ }, src_ip, pkt->get_dst_addr(), 0x01, reply, size, header_copy);

			delete [] header_copy;
		}

		delete [] reply;

		delete pkt;
	}
}

void icmp4::send_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t type, const uint8_t code, const packet *const p) const
{
	stats_inc_counter(icmp_transmit);

	uint8_t *out = new uint8_t[576]();

	out[0] = type;
	out[1] = code;
	out[2] = out[3] = 0; // checksum
	out[4] = out[5] = 0; // unused
	int mtu = idev->get_max_packet_size();
	out[6] = mtu >> 8; // next hop MTU
	out[7] = mtu & 255;

	auto org_header = p->get_header();
	auto org_payload = p->get_payload();

	memcpy(&out[8], org_header.first, org_header.second);

	int pl_size = std::min(8, org_payload.second);
	memcpy(&out[8 + org_header.second], org_payload.first, pl_size);

	int out_size = 8 + org_header.second + pl_size;
	out_size += out_size & 1;

	uint16_t checksum = ip_checksum((const uint16_t *)out, (out_size + 1) / 2);
	out[2] = checksum >> 8;
	out[3] = checksum;

	if (idev)
		idev->transmit_packet({ }, dst_ip, src_ip, 0x01, out, out_size, nullptr);

	delete [] out;
}

void icmp4::send_destination_port_unreachable(const any_addr & dst_ip, const any_addr & src_ip, const packet *const p) const
{
	send_packet(dst_ip, src_ip, 3, 3, p);
}

void icmp4::send_ttl_exceeded(const packet *const pkt) const
{
	send_packet(pkt->get_src_addr(), pkt->get_dst_addr(), 11, 0, pkt);
}
