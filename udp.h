// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <functional>
#include <map>
#include <shared_mutex>

#include "ip_protocol.h"
#include "packet.h"
#include "stats.h"

class icmp;
class ipv4;

typedef struct {
	std::function<void(const any_addr &, int, const any_addr &, int, packet *, void *private_data)> cb;
	void *private_data;
} cb_t;

class udp : public ip_protocol
{
private:
	icmp *const icmp_;

	// src ip, src port, dest ip (=local), dest port, payload-packet
	std::map<int, cb_t> callbacks;
	std::shared_mutex cb_lock;

	std::map<int, uint64_t> allocated_ports;
	std::mutex ports_lock;

	uint64_t *udp_requests { nullptr };
	uint64_t *udp_refused { nullptr };
	
	std::thread *th2 { nullptr };

public:
	udp(stats *const s, icmp *const icmp_);
	virtual ~udp();

	void add_handler(const int port, std::function<void(const any_addr &, int, const any_addr &, int, packet *, void *const pd)> h, void *const pd);
	void remove_handler(const int port);

	bool transmit_packet(const any_addr & dst_ip, const int dst_port, const any_addr & src_ip, const int src_port, const uint8_t *payload, const size_t pl_size);

	int allocate_port();
	void unallocate_port(const int port);
	void update_port_ts(const int port);
	void port_cleaner();

	virtual void operator()() override;
};
