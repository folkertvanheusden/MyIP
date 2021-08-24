// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <stdint.h>
#include <thread>

#include "any_addr.h"
#include "stats.h"

class packet;
class udp;

class sip
{
private:
	udp *const u;

	std::thread *th { nullptr };
	std::atomic_bool stop_flag { false };

public:
	sip(stats *const s, udp *const u);
	sip(const sip &) = delete;
	virtual ~sip();

	void input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p);

	void operator()();
};
