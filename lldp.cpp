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

void lldp::operator()()
{
	set_thread_name("myip-lldp");

	int      sleep_cnt = 0;

	uint8_t  target_mac[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

	any_addr dest_mac(target_mac, 6);

	uint8_t  payload[]    = { 0x00, 0x00 };
	size_t   payload_size = 2;

	while(!stop_flag) {
		// every 15s
		if (++sleep_cnt >= 30) {
			if (default_pdev)
				default_pdev->transmit_packet(dest_mac, my_mac, 0x88cc, payload, payload_size);

			sleep_cnt = 0;
		}	

		myusleep(500 * 1000);
	}
}
