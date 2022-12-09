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
#include "router.h"


class icmp;
class transport_layer;
class phys;

typedef struct {
	phys *interface;
	const packet *p;
} fifo_element_t;


class network_layer
{
protected:
	fifo<fifo_element_t> *pkts         { nullptr };

	phys                 *default_pdev { nullptr };

	std::map<uint8_t, transport_layer *> prot_map;

	icmp                 *icmp_        { nullptr };

	std::atomic_bool      stop_flag    { false   };

	router               *r            { nullptr };

public:
	network_layer(stats *const s, const std::string & stats_name, router *const r);
	virtual ~network_layer();

	void ask_to_stop() { stop_flag = true; }

	virtual any_addr get_addr() const = 0;

	void register_default_phys(phys *const p) { default_pdev = p; }

	void register_protocol(const uint8_t protocol, transport_layer *const p);
	transport_layer *get_transport_layer(const uint8_t protocol);

	void register_icmp(icmp *const icmp_) { this->icmp_ = icmp_; }

	virtual void queue_incoming_packet(phys *const interface, const packet *p);

	void queue_outgoing_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t *payload, const size_t pl_size);

	virtual bool transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) = 0;
	virtual bool transmit_packet(const any_addr & dst_ip,  const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) = 0;

	virtual int get_max_packet_size() const = 0;

	virtual void operator()() = 0;
};

uint16_t ip_checksum(const uint16_t *p, const size_t n);
