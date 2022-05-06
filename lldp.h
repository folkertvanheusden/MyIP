// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <map>
#include <stdint.h>
#include <string>

#include "phys.h"
#include "protocol.h"
#include "stats.h"


class lldp : public protocol
{
private:
	std::thread   *th { nullptr };

	const any_addr my_mac;

public:
	lldp(stats *const s, const any_addr & my_mac);
	virtual ~lldp();

	any_addr get_addr() const override { return any_addr(); }

	bool transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;
	bool transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;

	virtual int get_max_packet_size() const override { return 1500; }

	void queue_packet(phys *const interface, const packet *p) override;

	void operator()() override;
};
