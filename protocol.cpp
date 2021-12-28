// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <chrono>
#include <arpa/inet.h>

#include "ip_protocol.h"
#include "protocol.h"

constexpr size_t pkts_max_size { 512 };

protocol::protocol(stats *const s, const std::string & stats_name)
{
	pkts = new fifo<const packet *>(s, stats_name, pkts_max_size);
}

protocol::~protocol()
{
	delete pkts;
}

void protocol::register_protocol(const uint8_t protocol, ip_protocol *const p)
{
	prot_map.insert({ protocol, p });

	p->register_ip(this);
}

void protocol::queue_packet(const packet *p)
{
	pkts->try_put(p);
}

uint16_t ip_checksum(const uint16_t *p, const size_t n)
{
        uint32_t cksum = 0;

        for(size_t i=0; i<n; i++) 
                cksum += htons(p[i]);

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >>16);

        return ~cksum;
}
