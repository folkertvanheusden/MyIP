// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <stdint.h>
#include <thread>
#include <vector>

#include "packet.h"

class ip_protocol;
class phys;

class protocol
{
protected:
	std::thread *th { nullptr };
	std::atomic_bool stop_flag { false };

        std::mutex pkts_lock;
        std::condition_variable pkts_cv;
	std::vector<const packet *> pkts;

	phys *pdev { nullptr };

	std::map<uint8_t, ip_protocol *> prot_map;

public:
	protocol();
	virtual ~protocol();

	void register_phys(phys *const p) { pdev = p; }

	void register_protocol(const uint8_t protocol, ip_protocol *const p);

	void queue_packet(const packet *p);

	virtual void transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) = 0;
	virtual void transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) = 0;

	virtual int get_max_packet_size() const = 0;

	virtual void operator()() = 0;
};

uint16_t ip_checksum(const uint16_t *p, const size_t n);
