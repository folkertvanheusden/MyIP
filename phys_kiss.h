// (C) 2022-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#pragma once
#include <atomic>
#include <map>
#include <string>
#include <thread>

#include "any_addr.h"
#include "ax25.h"
#include "phys.h"
#include "network_layer.h"
#include "stats.h"

class phys_kiss : public phys
{
private:
	std::mutex        send_lock;

	const std::string descriptor;
	const any_addr    my_callsign;
	std::optional<std::pair<std::string, int> > beacon;
	const bool        add_callsign_repeaters { false };

	int               fd          { -1      };
	std::thread      *th_beacon   { nullptr };
	std::thread      *th_kiss_tcp { nullptr };

	void tcp_kiss_server();
	bool reconnect();
	bool transmit_ax25(const ax25_packet & a);
	void send_beacon();
	void handle_kiss(const int fd);

public:
	phys_kiss(const size_t dev_index, stats *const s, const std::string & descr, const any_addr & my_callsign, std::optional<std::pair<std::string, int> > beacon, router *const r, const bool add_callsign_repeaters);
	phys_kiss(const phys_kiss &) = delete;
	virtual ~phys_kiss();

	bool transmit_packet(const any_addr & dest_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size) override;

	virtual any_addr::addr_family get_phys_type() override { return any_addr::ax25; }

	void operator()() override;
};

bool process_kiss_packet(const timespec & ts, const std::vector<uint8_t> & in, std::map<uint16_t, network_layer *> *const prot_map, router *const r, phys *const source_phys, const std::optional<any_addr> & add_callsign);
