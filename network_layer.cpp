// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <chrono>
#include <arpa/inet.h>

#include "transport_layer.h"
#include "log.h"
#include "network_layer.h"


constexpr size_t pkts_max_size { 128 };

network_layer::network_layer(stats *const s, const std::string & stats_name, router *const r) : r(r)
{
	pkts = new fifo<fifo_element_t>(s, stats_name, pkts_max_size);
}

network_layer::~network_layer()
{
	delete pkts;
}

void network_layer::register_protocol(const uint8_t protocol, transport_layer *const p)
{
	prot_map.insert({ protocol, p });

	p->register_ip(this);
}

transport_layer *network_layer::get_transport_layer(const uint8_t protocol)
{
	auto it = prot_map.find(protocol);
	if (it == prot_map.end())
		return nullptr;

	return it->second;
}

void network_layer::queue_incoming_packet(phys *const interface, packet *p)
{
	if (pkts->try_put({ interface, p }) == false) {
		DOLOG(ll_debug, "network_layer: packet dropped\n");

		delete p;
	}
}

uint16_t ip_checksum(const uint16_t *const p, const size_t n)
{
        uint32_t cksum = 0;

        for(size_t i=0; i<n; i++) 
                cksum += htons(p[i]);

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += cksum >> 16;

        return ~cksum;
}
