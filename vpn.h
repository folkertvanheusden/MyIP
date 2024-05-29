// (C) 2024 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#pragma once

#include <atomic>
#include <stdint.h>
#include <thread>
#include <openssl/des.h>

#include "any_addr.h"
#include "application.h"
#include "stats.h"


class packet;
class phys_vpn_insertion_point;
class udp;

class vpn : public application
{
private:
	phys_vpn_insertion_point *const phys;
	DES_cblock                      key;
	DES_key_schedule                sched_encrypt;
	DES_key_schedule                sched_decrypt;
	udp                      *const u;
	const any_addr                  my_mac;
	const any_addr                  my_ip;
	const int                       my_port;
	const any_addr                  peer_ip;
	const int                       peer_port;
	uint8_t                         ivec_encrypt[8] { 0 };
	uint8_t                         ivec_decrypt[8] { 0 };

	uint64_t *vpn_recv { nullptr };
	uint64_t *vpn_send { nullptr };

public:
	vpn(phys_vpn_insertion_point *const phys, stats *const s, udp *const u, const any_addr & my_ip, const int my_port, const any_addr & peer_ip, const int peer_port, const std::string & psk);
	vpn(const vpn &) = delete;
	virtual ~vpn();

	void input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, session_data *const pd);

	bool transmit_packet(const uint16_t ether_type, const uint8_t *const payload, const size_t pl_size);

	void operator()();
};
