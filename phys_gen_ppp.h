// (C) 2022-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <string>
#include <termios.h>
#include <thread>

#include "any_addr.h"
#include "network_layer.h"
#include "phys.h"
#include "stats.h"


std::vector<uint8_t> unwrap_ppp_frame(const std::vector<uint8_t> & payload, const std::vector<uint8_t> & ACCM);

class phys_gen_ppp : public phys
{
protected:
	const any_addr my_mac;

	bool protocol_compression { false };
	bool ac_field_compression { false };
	bool lcp_options_acked    { false };
	bool ipcp_options_acked   { false };
	bool ipv6cp_options_acked { false };

	uint32_t magic { 0x1234abcd };

	std::vector<uint8_t> ACCM_tx;
	std::vector<uint8_t> ACCM_rx;

	const any_addr opponent_address;

	uint16_t fcstab[256] { 0 };

	void handle_lcp(const std::vector<uint8_t> & data);
	void handle_ccp(const std::vector<uint8_t> & data);
	void handle_ipcp(const std::vector<uint8_t> & data);
	void handle_ipv6cp(const std::vector<uint8_t> & data);

	void send_Xcp(const uint8_t code, const uint8_t identifier, const uint16_t protocol, const std::vector<uint8_t> & data);
	void send_rej(const uint16_t protocol, const uint8_t identifier, const std::vector<uint8_t> & options);
	void send_ack(const uint16_t protocol, const uint8_t identifier, const std::vector<uint8_t> & options);
	void send_nak(const uint16_t protocol, const uint8_t identifier, const std::vector<uint8_t> & options);

	std::vector<uint8_t> wrap_in_ppp_frame(const std::vector<uint8_t> & payload, const uint16_t protocol, const std::vector<uint8_t> & ACCM, const bool not_ppp_meta);

	void process_incoming_packet(std::vector<uint8_t> packet_buffer);

	virtual bool transmit_low(const std::vector<uint8_t> & payload, const uint16_t protocol, const std::vector<uint8_t> & ACCM, const bool not_ppp_meta) = 0;

public:
	phys_gen_ppp(const size_t dev_index, stats *const s, const std::string & name, const any_addr & my_mac, const any_addr & opponent_address);
	phys_gen_ppp(const phys_gen_ppp &) = delete;
	virtual ~phys_gen_ppp();

	void start() override;

	bool transmit_packet(const any_addr & dest_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size) override;

	any_addr::addr_family get_phys_type() override { return any_addr::mac; }

	virtual void operator()() override = 0;
};
