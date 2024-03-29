// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <map>
#include <optional>
#include <stdint.h>
#include <string>

#include "network_layer.h"
#include "phys.h"
#include "router.h"
#include "stats.h"
#include "time.h"


class lldp : public network_layer
{
private:
	std::thread   *th { nullptr };

	interruptable_sleep stop_flag;

	const any_addr my_mac;
	const any_addr mgmt_addr;
	const int      interface_idx;

	void add_tlv(std::vector<uint8_t> *const target, const uint8_t type, const std::vector<uint8_t> & payload);
	std::vector<uint8_t> generate_lldp_packet();

public:
	lldp(stats *const s, const any_addr & my_mac, const any_addr & mgmt_addr, const int interface_idx, router *const r);
	virtual ~lldp();

	any_addr get_addr() const override { return any_addr(); }

	bool transmit_packet(const std::optional<any_addr> & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;

	virtual int get_max_packet_size() const override { return 1500; }

	void queue_incoming_packet(phys *const interface, packet *p) override;

	void operator()() override;
};
