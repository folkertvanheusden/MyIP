// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <stdint.h>
#include <string>
#include <string.h>
#include <arpa/inet.h>

#include "lldp.h"
#include "log.h"
#include "phys.h"
#include "router.h"
#include "time.h"
#include "utils.h"


lldp::lldp(stats *const s, const any_addr & my_mac, const any_addr & mgmt_addr, const int interface_idx, router *const r) : network_layer(s, "lldp", r), my_mac(my_mac), mgmt_addr(mgmt_addr), interface_idx(interface_idx)
{
	th = new std::thread(std::ref(*this));
}

lldp::~lldp()
{
	stop_flag.signal_stop();

	th->join();
	delete th;
}

bool lldp::transmit_packet(const std::optional<any_addr> & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template)
{
	assert(0);

	return false;
}

void lldp::queue_incoming_packet(phys *const interface, packet *p)
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

	for(size_t i=0; i<in.size(); i++)
		out.push_back(in[i]);

	return out;
}

std::vector<uint8_t> lldp::generate_lldp_packet()
{
	std::vector<uint8_t> out;

	// CHASSIS ID
	std::vector<uint8_t> chassis_id { 4 };  // mac adress
	for(int i=0; i<6; i++)
		chassis_id.push_back(my_mac[i]);
	add_tlv(&out, 1, chassis_id);

	// PORT ID
	std::vector<uint8_t> port_id { 3 };  // mac adress
	for(int i=0; i<6; i++)
		port_id.push_back(my_mac[i]);
	add_tlv(&out, 2, port_id);

	// TTL
	std::vector<uint8_t> ttl;
	ttl.push_back(0);
	ttl.push_back(30);  // 30s
	add_tlv(&out, 3, ttl);

	// SYSTEM DESCRIPTION
	std::string description = "MyIP - www.vanheusden.com";
	std::vector<uint8_t> system_description = str_to_uvec(description);
	add_tlv(&out, 6, system_description);

	// MANAGEMENT ADDRESS
	std::vector<uint8_t> mgmt;

	mgmt.push_back(1 + mgmt_addr.get_len());  // the address
	mgmt.push_back(mgmt_addr.get_len() == 4 ? 1 : 6);  // '6' is a guess (for IPv6)
	for(int i=0; i<mgmt_addr.get_len(); i++)
		mgmt.push_back(mgmt_addr[i]);

	mgmt.push_back(2);  // ifIndex
	mgmt.push_back(interface_idx >> 24);
	mgmt.push_back(interface_idx >> 16);
	mgmt.push_back(interface_idx >>  8);
	mgmt.push_back(interface_idx);
	mgmt.push_back(0);  // oid string length

	add_tlv(&out, 8, mgmt);

	// end marker
	add_tlv(&out, 0, { });
	
	return out;
}

void lldp::operator()()
{
	set_thread_name("myip-lldp");

	any_addr dest_mac(any_addr::mac, std::initializer_list<uint8_t>({ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e }).begin());

	auto     payload      = generate_lldp_packet();

	for(;;) {
		if (stop_flag.sleep(15000))
			break;

		// every 15s
		if (default_pdev) {
			DOLOG(ll_debug, "lldp::operator: transmit LLDP packet\n");

			default_pdev->transmit_packet(dest_mac, my_mac, 0x88cc, payload.data(), payload.size());
		}
	}
}
