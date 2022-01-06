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
	icmp6 *icmp6_ { nullptr };

	ndp *indp { nullptr };

	const any_addr myip;

	uint64_t *ip_n_pkt { nullptr };
	uint64_t *ip_n_disc { nullptr };
	uint64_t *ip_n_del { nullptr };
	uint64_t *ip_n_out_req { nullptr };
	uint64_t *ip_n_out_disc { nullptr };
	uint64_t *ipv6_n_pkt { nullptr };
	uint64_t *ipv6_not_me { nullptr };
	uint64_t *ipv6_ttl_ex { nullptr };
	uint64_t *ipv6_unk_prot { nullptr };
	uint64_t *ipv6_n_tx { nullptr };
	uint64_t *ipv6_tx_err { nullptr };

	std::thread *ipv6_th { nullptr };
	std::atomic_bool ipv6_stop_flag { false };

public:
	ipv6(stats *const s, ndp *const indp, const any_addr & myip);
	virtual ~ipv6();

	any_addr get_addr() const override { return myip; }

	bool transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;
	bool transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;

	void register_icmp(icmp6 *const icmp6_) { this->icmp6_ = icmp6_; }

	virtual int get_max_packet_size() const override { return default_pdev->get_max_packet_size() - 40 /* 40 = size of IPv6 header */; }

	void operator()() override;
};
