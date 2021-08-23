// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <map>
#include <stdint.h>
#include <string>

#include "ndp.h"
#include "phys.h"
#include "protocol.h"
#include "ip_protocol.h"
#include "stats.h"

class arp;
class icmp6;

class ipv6 : public protocol
{
private:
	std::map<uint8_t, ip_protocol *> prot_map;
	icmp6 *icmp6_ { nullptr };

	ndp *indp { nullptr };

	const any_addr myip;

	uint64_t *ip_n_pkt { nullptr };
	uint64_t *ipv6_n_pkt { nullptr };
	uint64_t *ipv6_not_me { nullptr };
	uint64_t *ipv6_ttl_ex { nullptr };
	uint64_t *ipv6_unk_prot { nullptr };
	uint64_t *ipv6_n_tx { nullptr };
	uint64_t *ipv6_tx_err { nullptr };

public:
	ipv6(stats *const s, ndp *const indp, const any_addr & myip);
	virtual ~ipv6();

	void transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;
	void transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;

	void register_protocol(const uint8_t protocol, ip_protocol *const p);

	void register_icmp(icmp6 *const icmp6_) { this->icmp6_ = icmp6_; }

	virtual int get_max_packet_size() const override { return pdev->get_max_packet_size() - 40 /* 40 = size of IPv6 header */; }

	void operator()() override;
};
