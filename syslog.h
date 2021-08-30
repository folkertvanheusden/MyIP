// (C) 2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <stdint.h>
#include <thread>

#include "any_addr.h"
#include "stats.h"

class packet;
class udp;

class syslog_srv
{
private:
	udp *const u;

	std::thread *th { nullptr };
	std::atomic_bool stop_flag { false };

	uint64_t *syslog_srv_requests { nullptr };

public:
	syslog_srv(stats *const s, udp *const u);
	syslog_srv(const syslog_srv &) = delete;
	virtual ~syslog_srv();

	void input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, void *const pd);
};
