// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under AGPL v3.0
#include <chrono>

#include "protocol.h"

constexpr size_t pkts_max_size { 512 };

protocol::protocol()
{
}

protocol::~protocol()
{
}

void protocol::queue_packet(const packet *p)
{
	std::lock_guard<std::mutex> lck(pkts_lock);

	while (pkts.size() >= pkts_max_size) {
		delete pkts.at(0);

		pkts.erase(pkts.begin());
	}

	pkts.push_back(p);

	pkts_cv.notify_one();
}
