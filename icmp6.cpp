// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <unistd.h>

#include "icmp6.h"
#include "ipv4.h"
#include "ipv6.h"
#include "utils.h"

icmp6::icmp6(stats *const s, const any_addr & my_mac, const any_addr & my_ip) : my_mac(my_mac), my_ip(my_ip)
{
	icmp6_requests = s->register_stat("icmp6_requests");
	icmp6_transmit = s->register_stat("icmp6_transmit");
	icmp6_error    = s->register_stat("icmp6_error");

	constexpr const char rs_addr[] = "FF02:0000:0000:0000:000:0000:0000:0002";
	all_router_multicast_addr = parse_address(rs_addr, 16, ":", 16);

	th = new std::thread(std::ref(*this));

	th2 = new std::thread(&icmp6::router_solicitation, this);
}

icmp6::~icmp6()
{
	for(auto p : pkts)
		delete p;

	stop_flag = true;
	th->join();
	delete th;
}

void icmp6::operator()()
{
	set_thread_name("myip-icmp6");

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

		stats_inc_counter(icmp6_requests);

		const uint8_t type = p[0];

		if (type == 128) {  // echo request (PING)
			send_ping_reply(pkt);
		}
		else if (type == 135) {  // neighbor soliciation
			send_packet_neighbor_advertisement(pkt->get_src_mac_addr(), pkt->get_src_addr());
		}
		else {
			printf("type: %d, code: %d\n", p[0], p[1]);
		}

		delete pkt;
	}
}

void icmp6::send_packet(const any_addr *const dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t type, const uint8_t code, const uint32_t reserved, const uint8_t *const payload, const int payload_size) const
{
	stats_inc_counter(icmp6_transmit);

	int max_size = idev->get_max_packet_size() - 8;  // ICMPv6 are multiple of 8 bytes in size

	if (payload_size > max_size) {
		stats_inc_counter(icmp6_error);
		return;
	}

	uint8_t *out = new uint8_t[max_size]();

	out[0] = type;
	out[1] = code;
	out[2] = out[3] = 0; // checksum

	out[4] = reserved >> 24;
	out[5] = reserved >> 16;
	out[6] = reserved >>  8;
	out[7] = reserved;

	if (payload_size)
		memcpy(&out[8], payload, payload_size);

	int out_size = 8 + payload_size;
	if (out_size & 7)
		out_size += 8 - (out_size & 7);

	// calc checksum over pseudo header
	int temp_len = 40 + out_size;
	uint8_t *temp = new uint8_t[temp_len]();
	src_ip.get(&temp[0], 16);
	dst_ip.get(&temp[16], 16);
	temp[32] = out_size >> 24; // icmp6 len
	temp[33] = out_size >> 16;
	temp[34] = out_size >> 8;
	temp[35] = out_size;
	assert(temp[36] == 0x00);
	assert(temp[37] == 0x00);
	assert(temp[38] == 0x00);
	temp[39] = 58; // ICMP6 code
	memcpy(&temp[40], out, out_size);

	uint16_t checksum = ipv4_checksum((const uint16_t *)temp, temp_len / 2);
	out[2] = checksum >> 8;
	out[3] = checksum;

	delete [] temp;

	if (idev) {
		if (dst_mac)
			((ipv6 *)idev)->transmit_packet(*dst_mac, dst_ip, src_ip, 0x3a, out, out_size, nullptr);
		else
			idev->transmit_packet(dst_ip, src_ip, 0x3a, out, out_size, nullptr);
	}

	delete [] out;
}

void icmp6::send_packet_router_soliciation() const
{
	uint8_t dst_mac[6] = { 0x33, 0x33, all_router_multicast_addr[12], all_router_multicast_addr[13], all_router_multicast_addr[14], all_router_multicast_addr[15] };
	any_addr adst_mac(dst_mac, 6);

	uint8_t source_link_layer_address[8] = { 0x01, 0x01 };
	my_mac.get(&source_link_layer_address[2], 6);

	send_packet(&adst_mac, all_router_multicast_addr, my_ip, 133, 0, 0, source_link_layer_address, 8);
}

void icmp6::send_packet_neighbor_advertisement(const any_addr & peer_mac, const any_addr & peer_ip) const
{
	uint8_t target_link_layer_address[8] { 0x02, 0x01 };
	my_mac.get(&target_link_layer_address[2], 6);

	uint8_t payload[16 + 8] { 0x00 };
	my_ip.get(&payload[0], 16);
	memcpy(&payload[16], target_link_layer_address, 8);

	send_packet(&peer_mac, peer_ip, my_ip, 136, 0, 0x60000000, payload, 24);
}

void icmp6::send_ping_reply(const packet *const pkt) const
{
	auto request = pkt->get_payload();

	const uint8_t *p = request.first;
	uint32_t id_seq_nr = (p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7];

	const uint8_t *payload = request.second > 8 ? p + 8 : nullptr;

	send_packet(&pkt->get_src_mac_addr(), pkt->get_src_addr(), my_ip, 129, 0, id_seq_nr, payload, request.second - 8);
}

void icmp6::router_solicitation()
{
	set_thread_name("myip-icmp6-133");

	myusleep(500000);

	while(!stop_flag) {
		send_packet_router_soliciation();

		sleep(30);
	}
}
