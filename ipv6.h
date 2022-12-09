// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <map>
#include <stdint.h>
#include <string>

#include "ndp.h"
#include "phys.h"
#include "network_layer.h"
#include "transport_layer.h"
#include "stats.h"


class arp;

class ipv6 : public network_layer
{
private:
	std::vector<std::thread *> ths;

	ndp   *indp   { nullptr };

	const any_addr myip;

	uint64_t *ip_n_pkt      { nullptr };
	uint64_t *ip_n_disc     { nullptr };
	uint64_t *ip_n_del      { nullptr };
	uint64_t *ip_n_out_req  { nullptr };
	uint64_t *ip_n_out_disc { nullptr };
	uint64_t *ipv6_n_pkt    { nullptr };
	uint64_t *ipv6_not_me   { nullptr };
	uint64_t *ipv6_ttl_ex   { nullptr };
	uint64_t *ipv6_unk_prot { nullptr };
	uint64_t *ipv6_n_tx     { nullptr };
	uint64_t *ipv6_tx_err   { nullptr };

public:
	ipv6(stats *const s, ndp *const indp, const any_addr & myip);
	virtual ~ipv6();

	any_addr get_addr() const override { return myip; }

	bool transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;
	bool transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;

	virtual int get_max_packet_size() const override { return default_pdev->get_max_packet_size() - 40 /* 40 = size of IPv6 header */; }

	void operator()() override;
};
