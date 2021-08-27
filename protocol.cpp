// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <chrono>
#include <arpa/inet.h>

#include "ip_protocol.h"
#include "protocol.h"

constexpr size_t pkts_max_size { 512 };

protocol::protocol()
{
}

protocol::~protocol()
{
}

void protocol::register_protocol(const uint8_t protocol, ip_protocol *const p)
{
	prot_map.insert({ protocol, p });

	p->register_ip(this);
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

uint16_t ip_checksum(const uint16_t *p, const size_t n)
{
        uint32_t sum = 0;

        for(size_t i=0; i<n; i++) {
                sum += htons(p[i]);

                if (sum & 0x80000000)   /* if high order bit set, fold */
                        sum = (sum & 0xFFFF) + (sum >> 16);
        }

        while(sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        return ~sum;
}
