#pragma once

#include "any_addr.h"
#include "network_layer.h"
#include "router.h"
#include "stats.h"


class mac_resolver : public network_layer
{
protected:
	fifo<fifo_element_t> *pkts { nullptr };

public:
	mac_resolver(stats *const s, router *const r);
	virtual ~mac_resolver();

	virtual any_addr get_mac(const any_addr & ip) = 0;

	void queue_incoming_packet(phys *const interface, const packet *p) override;

	bool transmit_packet(const std::optional<any_addr> & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;

	int get_max_packet_size() const override;

	void operator()() override;
};
