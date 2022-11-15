// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <map>
#include <mutex>
#include <stdint.h>
#include <thread>
#include <vector>

#include "fifo.h"
#include "packet.h"

class ip_protocol;
class phys;

typedef struct {
	phys *interface;
	const packet *p;
} fifo_element_t;

class protocol
{
protected:
	fifo<fifo_element_t> *pkts { nullptr };

	phys *default_pdev { nullptr };

	std::map<uint8_t, ip_protocol *> prot_map;

	std::atomic_bool stop_flag { false };

public:
	protocol(stats *const s, const std::string & stats_name);
	virtual ~protocol();

	void ask_to_stop() { stop_flag = true; }

	virtual any_addr get_addr() const = 0;

	void register_default_phys(phys *const p) { default_pdev = p; }

	void register_protocol(const uint8_t protocol, ip_protocol *const p);
	ip_protocol *get_ip_protocol(const uint8_t p);

	virtual void queue_packet(phys *const interface, const packet *p);

	virtual bool transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) = 0;
	virtual bool transmit_packet(const any_addr & dst_ip,  const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) = 0;

	virtual int get_max_packet_size() const = 0;

	virtual void operator()() = 0;
};

uint16_t ip_checksum(const uint16_t *p, const size_t n);
