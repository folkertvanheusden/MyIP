// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <stdint.h>
#include <thread>
#include <vector>

#include "packet.h"

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

public:
	protocol();
	virtual ~protocol();

	void register_phys(phys *const p) { pdev = p; }

	void queue_packet(const packet *p);

	virtual void operator()() = 0;
};
