// (C) 2024 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <algorithm>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "log.h"
#include "net.h"
#include "phys_vpn_insertion_point.h"
#include "packet.h"
#include "tty.h"
#include "utils.h"


phys_vpn_insertion_point::phys_vpn_insertion_point(const size_t dev_index, stats *const s, const std::string & dev_name, router *const r, const any_addr & my_mac):
	phys(dev_index, s, "vpn-" + dev_name, r),
	my_mac(my_mac)
{
}

phys_vpn_insertion_point::~phys_vpn_insertion_point()
{
}

void phys_vpn_insertion_point::start()
{
	th = new std::thread(std::ref(*this));
}

void phys_vpn_insertion_point::configure_endpoint(vpn *const v)
{
	this->v = v;
}

bool phys_vpn_insertion_point::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size)
{
	if (!v)
		return false;

	stats_add_counter(phys_ifOutOctets,   pl_size);
	stats_add_counter(phys_ifHCOutOctets, pl_size);
	stats_inc_counter(phys_ifOutUcastPkts);

	// loopback
	if (dst_mac == my_mac) {
		CDOLOG(ll_debug, "[VPN]", "transmit (loopback!) packet %s -> %s\n", src_mac.to_str().c_str(), dst_mac.to_str().c_str());
		return insert_packet(dst_mac, src_mac, ether_type, payload, pl_size);
	}

	CDOLOG(ll_debug, "[VPN]", "transmit packet %s -> %s\n", src_mac.to_str().c_str(), dst_mac.to_str().c_str());

	return v->transmit_packet(ether_type, payload, pl_size);
}

void phys_vpn_insertion_point::operator()()
{
	// not used
}

bool phys_vpn_insertion_point::insert_packet(const uint16_t ether_type, const uint8_t *const payload, const size_t pl_size)
{
	return insert_packet(gen_opponent_mac(my_mac), my_mac, ether_type, payload, pl_size);
}

bool phys_vpn_insertion_point::insert_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *const payload, const size_t pl_size)
{
	timespec ts { 0, 0 };
	if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		CDOLOG(ll_warning, "[vpn]", "clock_gettime failed: %s\n", strerror(errno));

        auto it = prot_map.find(ether_type);
        if (it == prot_map.end()) {
                CDOLOG(ll_info, "[vpn]", "dropping ethernet packet with ether type %04x (= unknown) and size %zu\n", ether_type, pl_size);
                return false;
        }

        packet *p = new packet(ts, dst_mac, src_mac, payload, pl_size, nullptr, 0, "vpn");

        it->second->queue_incoming_packet(this, p);

	return true;
}
