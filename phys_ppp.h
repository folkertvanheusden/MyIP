// (C) 2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <mutex>
#include <string>
#include <termios.h>
#include <thread>

#include "any_addr.h"
#include "phys_slip.h"
#include "protocol.h"
#include "stats.h"

class phys_ppp : public phys_slip
{
private:
	bool emulate_modem_xp { false };
	bool protocol_compression { false };
	bool ac_field_compression { false };
	uint32_t magic { 0x1234abcd };
	std::vector<uint8_t> ACCM_tx, ACCM_rx;

	uint16_t fcstab[256] { 0 };

	std::mutex send_lock;

	void handle_lcp(const std::vector<uint8_t> & data);
	std::vector<uint8_t> wrap_in_ppp_frame(const std::vector<uint8_t> & payload, const uint16_t protocol, const std::vector<uint8_t> ACCM, const bool apply_compression);

public:
	phys_ppp(stats *const s, const std::string & dev_name, const int bps, const any_addr & my_mac, const bool emulate_modem_xp);
	phys_ppp(const phys_ppp &) = delete;
	virtual ~phys_ppp();

	void start() override;

	bool transmit_packet(const any_addr & dest_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size) override;

	void operator()() override;
};
