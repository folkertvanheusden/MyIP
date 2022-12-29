// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <mutex>
#include <stdint.h>
#include <thread>
#include <vector>

#include "fifo.h"
#include "packet.h"
#include "network_layer.h"


class ipv4;

class transport_layer
{
protected:
	std::vector<std::thread *> ths;
	std::atomic_bool           stop_flag { false };

	fifo<packet *>            *pkts      { nullptr };

	network_layer             *idev      { nullptr };

public:
	transport_layer(stats *const s, const std::string & stats_name);
	virtual ~transport_layer();

	void ask_to_stop() { stop_flag = true; }

	void register_ip(network_layer *const p) { idev = p; }

	any_addr get_ip_address() const { return idev->get_addr(); }

	void queue_packet(packet *p);

	virtual void operator()() = 0;
};

uint16_t tcp_udp_checksum(const any_addr & src_addr, const any_addr & dst_addr, const bool tcp, const uint8_t *const tcp_payload, const int len);
