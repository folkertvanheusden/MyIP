// (C) 2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <map>
#include <string>
#include <termios.h>
#include <thread>

#include "any_addr.h"
#include "phys.h"
#include "protocol.h"
#include "stats.h"

class phys_slip : public phys
{
private:
	const any_addr my_mac;
	int fd { -1 };

public:
	phys_slip(stats *const s, const std::string & dev_name, const int bps, const any_addr & my_mac);
	phys_slip(const phys_slip &) = delete;
	virtual ~phys_slip();

	bool transmit_packet(const any_addr & dest_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size);

	void operator()();
};
