// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <stdint.h>
#include <string>
#include <string.h>
#include <arpa/inet.h>

#include "lldp.h"
#include "phys.h"
#include "utils.h"

lldp::lldp(stats *const s, const any_addr & my_mac) : protocol(s, "lldp"), my_mac(my_mac)
{
	th = new std::thread(std::ref(*this));
}

lldp::~lldp()
{
	stop_flag = true;

	th->join();
	delete th;
}

bool lldp::transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
	return false;
}

bool lldp::transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
	return false;
}

void lldp::queue_packet(phys *const interface, const packet *p)
{
	delete p;
}

void lldp::add_tlv(std::vector<uint8_t> *const target, const uint8_t type, const std::vector<uint8_t> & payload)
{
	uint16_t header = (type << 9) | payload.size();
	target->push_back(header >> 8);
	target->push_back(header);

	std::copy(payload.begin(), payload.end(), std::back_inserter(*target));
}

std::vector<uint8_t> str_to_uvec(const std::string & in)
{
	std::vector<uint8_t> out;

	for(int i=0; i<in.size(); i++)
		out.push_back(in[i]);

	return out;
}

std::vector<uint8_t> lldp::generate_lldp_packet()
{
	std::vector<uint8_t> out;

	std::vector<uint8_t> chassis_id { 4 };
	for(int i=0; i<6; i++)
		chassis_id.push_back(my_mac[i]);
	add_tlv(&out, 1, chassis_id);

	std::vector<uint8_t> port_id { 3 };
	for(int i=0; i<6; i++)
		port_id.push_back(my_mac[i]);
	add_tlv(&out, 2, port_id);

	std::vector<uint8_t> ttl;
	ttl.push_back(0);
	ttl.push_back(30);
	add_tlv(&out, 3, ttl);

	std::string description = "MyIP - www.vanheusden.com";
	std::vector<uint8_t> system_description = str_to_uvec(description);
	add_tlv(&out, 6, system_description);

	add_tlv(&out, 0, { });
	
	return out;
}

void lldp::operator()()
{
	set_thread_name("myip-lldp");

	int      sleep_cnt = 0;

	uint8_t  target_mac[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e };

	any_addr dest_mac(target_mac, 6);

	auto     payload      = generate_lldp_packet();

	while(!stop_flag) {
		// every 15s
		if (++sleep_cnt >= 30) {
			if (default_pdev)
				default_pdev->transmit_packet(dest_mac, my_mac, 0x88cc, payload.data(), payload.size());

			sleep_cnt = 0;
		}	

		myusleep(500 * 1000);
	}
}
