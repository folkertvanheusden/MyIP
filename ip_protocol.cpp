// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <chrono>

#include "ip_protocol.h"

constexpr size_t pkts_max_size { 512 };

ip_protocol::ip_protocol()
{
}

ip_protocol::~ip_protocol()
{
	for(auto p : pkts)
		delete p;
}

void ip_protocol::queue_packet(const packet *p)
{
	std::lock_guard<std::mutex> lck(pkts_lock);

	while (pkts.size() >= pkts_max_size) {
		delete pkts.at(0);

		pkts.erase(pkts.begin());
	}

	pkts.push_back(p);

	pkts_cv.notify_one();
}
