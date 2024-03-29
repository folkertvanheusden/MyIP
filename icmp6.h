// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <thread>

#include "any_addr.h"
#include "transport_layer.h"
#include "icmp.h"
#include "mac_resolver.h"
#include "ndp.h"
#include "stats.h"


class phys;
class router;

class icmp6 : public icmp
{
private:
	const any_addr my_mac;
	const any_addr my_ip;
	
	router   *const r        { nullptr };
	phys     *const interface{ nullptr };

	uint64_t *icmp6_requests { nullptr };
	uint64_t *icmp6_transmit { nullptr };
	uint64_t *icmp6_error    { nullptr };

	any_addr all_router_multicast_addr;

	ndp      *indp           { nullptr };

	void process_router_advertisement(const packet *const pkt);

	void send_packet(const any_addr *const dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t type, const uint8_t code, const uint32_t reserved, const uint8_t *const payload, const int payload_size) const;

	void send_packet_router_soliciation() const;
	void send_packet_neighbor_advertisement(const any_addr & peer_mac, const any_addr & peer_ip) const;
	void send_ping_reply(const packet *const pkt) const;

	void send_destination_port_unreachable(const any_addr & dst_ip, const any_addr & src_ip, const packet *const p) const override;

	void router_solicitation();

public:
	icmp6(stats *const s, const any_addr & my_mac, const any_addr & my_ip, router *const r, phys *const interface, const int n_threads);
	virtual ~icmp6();

	void send_ttl_exceeded(const packet *const pkt) const;
	void send_packet_neighbor_solicitation(const any_addr & peer_ip) const;

	void operator()() override;
};
