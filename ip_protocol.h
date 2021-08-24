// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <stdint.h>
#include <thread>
#include <vector>

#include "packet.h"
#include "protocol.h"

class ipv4;

class ip_protocol
{
protected:
	std::thread *th { nullptr };
	std::atomic_bool stop_flag { false };

        std::mutex pkts_lock;
        std::condition_variable pkts_cv;
	std::vector<const packet *> pkts;

	protocol *idev { nullptr };

public:
	ip_protocol();
	virtual ~ip_protocol();

	void register_ip(protocol *const p) { idev = p; }

	void queue_packet(const packet *p);

	virtual void operator()() = 0;
};

uint16_t tcp_udp_checksum(const any_addr & src_addr, const any_addr & dst_addr, const bool tcp, const uint8_t *const tcp_payload, const int len);
