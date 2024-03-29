// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <stdint.h>
#include <thread>

#include "any_addr.h"
#include "application.h"
#include "stats.h"

class packet;
class udp;

class syslog_srv : public application
{
private:
	uint64_t *syslog_srv_requests { nullptr };

public:
	syslog_srv(stats *const s);
	syslog_srv(const syslog_srv &) = delete;
	virtual ~syslog_srv();

	void input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, session_data *const pd);
};
