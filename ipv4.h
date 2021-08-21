// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <map>
#include <stdint.h>
#include <string>

#include "protocol.h"
#include "ip_protocol.h"
#include "stats.h"

std::string ip_to_str(std::pair<const uint8_t *, int> & src_addr);
uint16_t ipv4_checksum(const uint16_t *p, const size_t n);

class arp;
class icmp;

class ipv4 : public protocol
{
private:
	std::map<uint8_t, ip_protocol *> prot_map;
	arp *const iarp;
	icmp *icmp_ { nullptr };

	uint8_t myip[4];

	uint64_t *ip_n_pkt { nullptr };
	uint64_t *ipv4_n_pkt { nullptr };
	uint64_t *ipv4_not_me { nullptr };
	uint64_t *ipv4_ttl_ex { nullptr };
	uint64_t *ipv4_unk_prot { nullptr };
	uint64_t *ipv4_n_tx { nullptr };

	void send_ttl_exceeded(const packet *const pkt) const;

public:
	ipv4(stats *const s, arp *const iarp, const uint8_t myip[4]);
	virtual ~ipv4();

	void transmit_packet(const uint8_t *dst_ip, const uint8_t *src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template = nullptr);

	void register_protocol(const uint8_t protocol, ip_protocol *const p);

	void register_icmp(icmp *const icmp_) { this->icmp_ = icmp_; }

	void operator()() override;
};
