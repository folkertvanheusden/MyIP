// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <map>
#include <stdint.h>
#include <string>

#include "phys.h"
#include "protocol.h"
#include "ip_protocol.h"
#include "stats.h"

class arp;
class icmp;

class ipv4 : public protocol
{
private:
	arp *const iarp;
	icmp *icmp_ { nullptr };

	const any_addr myip;

	uint64_t *ip_n_pkt { nullptr };
	uint64_t *ip_n_disc { nullptr };
	uint64_t *ip_n_del { nullptr };
	uint64_t *ip_n_out_req { nullptr };
	uint64_t *ip_n_out_disc { nullptr };
	uint64_t *ipv4_n_pkt { nullptr };
	uint64_t *ipv4_not_me { nullptr };
	uint64_t *ipv4_ttl_ex { nullptr };
	uint64_t *ipv4_unk_prot { nullptr };
	uint64_t *ipv4_n_tx { nullptr };
	uint64_t *ipv4_tx_err { nullptr };

	std::thread *ipv4_th { nullptr };
	std::atomic_bool ipv4_stop_flag { false };

	void send_ttl_exceeded(const packet *const pkt) const;

public:
	ipv4(stats *const s, arp *const iarp, const any_addr & myip);
	virtual ~ipv4();

	void transmit_packet(const any_addr & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;
	void transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;

	void register_icmp(icmp *const icmp_) { this->icmp_ = icmp_; }

	virtual int get_max_packet_size() const override { return pdev->get_max_packet_size() - 20 /* 20 = size of IPv4 header (without options, as MyIP does) */; }

	void operator()() override;
};
