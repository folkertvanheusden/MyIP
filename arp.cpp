// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <string.h>

#include "arp.h"
#include "ax25.h"
#include "log.h"
#include "net.h"
#include "phys.h"
#include "router.h"
#include "time.h"
#include "utils.h"


constexpr size_t pkts_max_size { 256 };

arp::arp(stats *const s, phys *const interface, const any_addr & my_mac, const any_addr & my_ip) :
	mac_resolver(s, nullptr),
	my_mac(my_mac), my_ip(my_ip),
	interface(interface)
{
	// 1.3.6.1.4.1.57850.1.11: arp
	arp_requests = s->register_stat("arp_requests", "1.3.6.1.4.1.57850.1.11.1");
	arp_for_me   = s->register_stat("arp_for_me",   "1.3.6.1.4.1.57850.1.11.2");

	arp_th = new std::thread(std::ref(*this));
}

arp::~arp()
{
	pkts->interrupt();

	arp_th->join();
	delete arp_th;
}

void arp::operator()()
{
	set_thread_name("myip-arp");

	for(;;) {
		auto po = pkts->get();
		if (!po.has_value())
			break;

		const packet *pkt = po.value().p;

		stats_inc_counter(arp_requests);

		const uint8_t *const p    = pkt->get_data();
		const int            size = pkt->get_size();

		if (size < 6) {
			DOLOG(ll_debug, "ARP: packet too small (%d bytes)\n", size);
			delete pkt;
			continue;
		}

		uint8_t hw_size = p[4];
		uint8_t p_size  = p[5];

                uint16_t sha_offset = 8;
                uint16_t spa_offset = 8 + hw_size;
                uint16_t tha_offset = spa_offset + p_size;
                uint16_t tpa_offset = tha_offset + hw_size;
                uint16_t end_offset = tpa_offset + p_size;

		if (size < end_offset) {
			DOLOG(ll_debug, "ARP: invalid packet size (%d bytes, expected %d)\n", size, end_offset);
			delete pkt;
			continue;
		}

		uint16_t ether_type = (p[2] << 8) + p[3];

		if ((ether_type == 0x0800 && p_size != 4) || (ether_type == 0x08ff && hw_size != 7) || (ether_type == 0x00cc && hw_size != 7)) {
			DOLOG(ll_debug, "ARP: ethertype p/hw-size mismatch\n");
			delete pkt;
			continue;
		}

		uint16_t request = (p[6] << 8) + p[7];

		any_addr THA(any_addr::mac,  &p[tha_offset]);
		any_addr SHA(any_addr::mac,  &p[sha_offset]);
		any_addr TPA(any_addr::ipv4, &p[tpa_offset]);
		any_addr SPA(any_addr::ipv4, &p[spa_offset]);

		bool is_gratuitous = (request == 0x0001 || request == 0x0002) &&
				memcmp(&p[tha_offset], "\xff\xff\xff\xff\xff\xff", 6) == 0 &&
				TPA == SPA;

		DOLOG(ll_debug, "ARP%04x: THA: %s, SHA: %s, TPA: %s, SPA: %s%s\n",
				request,
				THA.to_str().c_str(),
				SHA.to_str().c_str(),
				TPA.to_str().c_str(),
				SPA.to_str().c_str(),
				is_gratuitous ? ", gratuitous" : ""
				);

		if (is_gratuitous)
			update_cache(SHA, SPA, interface, false);

		if (request == 0x0001) {  // request
			any_addr for_whom = TPA;

			if (for_whom == my_ip)  // am I the target?
			{
				stats_inc_counter(arp_for_me);

				uint8_t *reply = duplicate(p, size);

				swap_mac(&reply[sha_offset], &reply[tha_offset]); // arp addresses

				// my MAC address
				if (ether_type == 0x0800)  // ipv4
					my_mac.get(&reply[sha_offset], 6);
				else if (ether_type == 0x08ff || ether_type == 0x00cc)  // AX.25
					my_mac.get(&reply[sha_offset], 7);
				else
					DOLOG(ll_error, "ARP: unexpected ether-type %04x\n", ether_type);

				reply[7] = 0x02; // reply

				swap_ipv4(&reply[spa_offset], &reply[tpa_offset]);

				po.value().interface->transmit_packet(pkt->get_src_addr(), my_mac, 0x0806, reply, size);

				delete [] reply;
			}
		}
		else if (request == 0x0002) {  // reply
			auto dst_mac = pkt->get_dst_addr();

			any_addr work_ip = SPA;

			any_addr work_mac;

			if (ether_type == 0x0800)
				work_mac = any_addr(any_addr::mac,  &p[sha_offset]);
			else if (ether_type == 0x08ff || ether_type == 0x00cc)  // AX.25
				work_mac = any_addr(any_addr::ax25, &p[sha_offset]);
			else
				DOLOG(ll_error, "ARP: unexpected ether-type %04x\n", ether_type);

			DOLOG(ll_debug, "arp::operator: received arp-reply for %s (is at %s)\n", work_ip.to_str().c_str(), work_mac.to_str().c_str());

			std::unique_lock lck(work_lock);

			auto it = work.find(work_ip);  // IP to resolve
			if (it != work.end())
				it->second = mac_resolver_result({ work_mac });

			work_cv.notify_all();
		}

		delete pkt;
	}
}

bool arp::send_request(const any_addr & ip, const any_addr::addr_family af)
{
	uint8_t request[44] { 0 };

	uint8_t hw_size = 0;

	if (af == any_addr::mac)
		request[1] = 1, hw_size = 6;  // HTYPE (Ethernet)
	else if (af == any_addr::ax25)
		request[1] = 3, hw_size = 7;  // HTYPE (AX.25)
	else {
		DOLOG(ll_warning, "ARP::send_request: unsupported address family %d\n", af);
		return false;
	}

	uint8_t p_size = 0;

	// PTYPE
	if (ip.get_family() == any_addr::ipv4) {
		if (af == any_addr::ax25)
			request[2] = 0x00, request[3] = 0xcc;
		else
			request[2] = 0x08, request[3] = 0x00;
		
		p_size = 4;
	}
	else {
		DOLOG(ll_warning, "ARP::send_request: don't know how to resolve \"%s\" with ARP", ip.to_str().c_str());
		return false;
	}

	request[4] = hw_size;  // HLEN
	request[5] = p_size;  // PLEN

	request[6] = 0x00;  // OPER
	request[7] = 1;

	uint16_t sha_offset = 8;
	uint16_t spa_offset = 8 + hw_size;
	uint16_t tha_offset = spa_offset + p_size;
	uint16_t tpa_offset = tha_offset + hw_size;
	uint16_t end        = tpa_offset + p_size;

	my_mac.get(&request[sha_offset], hw_size);  // SHA

	my_ip.get(&request[spa_offset], p_size);  // SPA

	ip.get(&request[tpa_offset], p_size);  // TPA

	any_addr dest_mac;

	if (af == any_addr::mac)
		dest_mac = any_addr(any_addr::mac, std::initializer_list<uint8_t>({ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }).begin());
	else if (af == any_addr::ax25)
		dest_mac = ax25_address("QST", 0, true, false).get_any_addr();
	else
		DOLOG(ll_warning, "ARP::send_request: address family %d unexpected\n", af);

	DOLOG(ll_info, "ARP::send_request: %s -> %s to resolve %s (%d bytes)\n", my_mac.to_str().c_str(), dest_mac.to_str().c_str(), ip.to_str().c_str(), end);

	return interface->transmit_packet(dest_mac, my_mac, 0x0806, request, end);
}

std::optional<any_addr> arp::check_special_ip_addresses(const any_addr & ip, const any_addr::addr_family family)
{
	if ((ip[0] & 0xf0) == 224) {  // multicast
		if (family == any_addr::mac)
			return any_addr(any_addr::mac, std::initializer_list<uint8_t>({ 0x01, 0x00, 0x5e, ip[1], ip[2], ip[3] }).begin());

		if (family == any_addr::ax25) {
			ax25_address bc("QST", 0, false, false);

			return bc.get_any_addr();
		}
	}

	// TODO depending on netmask
	if (ip[0] == 255 && ip[1] == 255 && ip[2] == 255 && ip[3] == 255)  // broadcast
		return any_addr(any_addr::mac, std::initializer_list<uint8_t>({ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }).begin());

	return { };
}
