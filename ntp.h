// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <stdint.h>
#include <thread>
#include "stats.h"

class packet;
class udp;

class ntp
{
private:
	udp *const u;

	uint8_t upstream_ntp_server[4] { 0 };

	const bool broadcast;

	std::thread *th { nullptr };
	std::atomic_bool stop_flag { false };

	uint64_t *ntp_requests { nullptr }, *ntp_invalid { nullptr }, *ntp_time_req { nullptr };
	uint64_t *ntp_t_req_v[8] { nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr };
	uint64_t *ntp_broadcast { nullptr };

public:
	ntp(stats *const s, udp *const u, const uint8_t upstream_ntp_server[4], const bool broadcast);
	ntp(const ntp &) = delete;
	virtual ~ntp();

	void input(const uint8_t *src_ip, int src_port, const uint8_t *dst_ip, int dst_port, packet *p);

	void operator()();
};
