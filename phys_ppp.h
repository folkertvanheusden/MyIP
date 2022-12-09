// (C) 2022-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <termios.h>
#include <thread>

#include "any_addr.h"
#include "phys_slip.h"
#include "network_layer.h"
#include "stats.h"


class phys_ppp : public phys_slip
{
private:
	bool emulate_modem_xp { false };
	bool protocol_compression { false };
	bool ac_field_compression { false };
	bool lcp_options_acked { false };
	bool ipcp_options_acked { false };
	bool ipv6cp_options_acked { false };
	uint32_t magic { 0x1234abcd };
	std::vector<uint8_t> ACCM_tx, ACCM_rx;
	const any_addr opponent_address;

	uint16_t fcstab[256] { 0 };

	std::mutex send_lock;

	void handle_lcp(const std::vector<uint8_t> & data);
	void handle_ccp(const std::vector<uint8_t> & data);
	void handle_ipcp(const std::vector<uint8_t> & data);
	void handle_ipv6cp(const std::vector<uint8_t> & data);

	void send_Xcp(const uint8_t code, const uint8_t identifier, const uint16_t protocol, const std::vector<uint8_t> & data);
	void send_rej(const uint16_t protocol, const uint8_t identifier, const std::vector<uint8_t> & options);
	void send_ack(const uint16_t protocol, const uint8_t identifier, const std::vector<uint8_t> & options);
	void send_nak(const uint16_t protocol, const uint8_t identifier, const std::vector<uint8_t> & options);

	std::vector<uint8_t> wrap_in_ppp_frame(const std::vector<uint8_t> & payload, const uint16_t protocol, const std::vector<uint8_t> & ACCM, const bool not_ppp_meta);

public:
	phys_ppp(const size_t dev_index, stats *const s, const std::string & dev_name, const int bps, const any_addr & my_mac, const bool emulate_modem_xp, const any_addr & opponent_address);
	phys_ppp(const phys_ppp &) = delete;
	virtual ~phys_ppp();

	void start() override;

	bool transmit_packet(const any_addr & dest_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size) override;

	void operator()() override;
};
