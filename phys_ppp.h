// (C) 2022-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <termios.h>
#include <thread>

#include "any_addr.h"
#include "network_layer.h"
#include "phys_gen_ppp.h"
#include "stats.h"


class phys_ppp : public phys_gen_ppp
{
private:
	std::mutex send_lock;

	int        fd               { -1    };
	bool       emulate_modem_xp { false };

protected:
	bool transmit_low(const std::vector<uint8_t> & payload, const uint16_t protocol, const std::vector<uint8_t> & ACCM, const bool not_ppp_meta) override;

public:
	phys_ppp(const size_t dev_index, stats *const s, const std::string & dev_name, const int bps, const any_addr & my_mac, const bool emulate_modem_xp, const any_addr & opponent_address);
	phys_ppp(const phys_ppp &) = delete;
	virtual ~phys_ppp();

	void operator()() override;
};
