// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <functional>
#include <map>
#include <shared_mutex>

#include "buffer.h"
#include "ip_protocol.h"
#include "packet.h"
#include "stats.h"

class icmp;
class ipv4;

class sctp : public ip_protocol
{
private:
	icmp *const icmp_;

	std::map<int, uint64_t> allocated_ports;
	std::mutex              ports_lock;

	uint64_t *sctp_msgs        { nullptr };
	uint64_t *sctp_failed_msgs { nullptr };

	std::pair<uint16_t, buffer> get_parameter(buffer & chunk_payload);
	void                        init(buffer & in);

public:
	sctp(stats *const s, icmp *const icmp_);
	virtual ~sctp();

	void add_handler(const int port, std::function<void(const any_addr &, int, const any_addr &, int, packet *, void *const pd)> h, void *const pd);
	void remove_handler(const int port);

	bool transmit_packet(const any_addr & dst_ip, const int dst_port, const any_addr & src_ip, const int src_port, const uint8_t *payload, const size_t pl_size);

	virtual void operator()() override;
};
