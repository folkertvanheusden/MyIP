// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <stdint.h>
#include <thread>

#include "any_addr.h"
#include "stats.h"

class packet;
class udp;

class ntp
{
private:
	udp *const u;

	const any_addr my_ip, upstream_ntp_server;

	const bool broadcast;

	std::thread *th { nullptr };
	std::atomic_bool stop_flag { false };

	uint64_t *ntp_requests { nullptr }, *ntp_invalid { nullptr }, *ntp_time_req { nullptr };
	uint64_t *ntp_t_req_v[8] { nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr };
	uint64_t *ntp_broadcast { nullptr };

public:
	ntp(stats *const s, udp *const u, const any_addr & my_ip, const any_addr & upstream_ntp_server, const bool broadcast);
	ntp(const ntp &) = delete;
	virtual ~ntp();

	void input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p);

	void operator()();
};
