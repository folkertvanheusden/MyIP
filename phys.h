// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <map>
#include <string>
#include <thread>

#include "any_addr.h"
#include "network_layer.h"
#include "stats.h"


class phys
{
protected:
	std::thread     *th        { nullptr };
	std::atomic_bool stop_flag { false };

	uint64_t *phys_recv_frame  { nullptr };
	uint64_t *phys_invl_frame  { nullptr };
	uint64_t *phys_ign_frame   { nullptr };

	uint64_t *phys_ifInOctets     { nullptr };
	uint64_t *phys_ifHCInOctets   { nullptr };
	uint64_t *phys_ifInUcastPkts  { nullptr };
	uint64_t *phys_ifOutOctets    { nullptr };
	uint64_t *phys_ifHCOutOctets  { nullptr };
	uint64_t *phys_ifOutUcastPkts { nullptr };

	int       mtu_size         { 0 };

	std::map<uint16_t, network_layer *> prot_map;

	const size_t dev_index     { 0 };

	const std::string name;

public:
	phys(const size_t dev_index, stats *const s, const std::string & name);
	phys(const phys &) = delete;
	virtual ~phys();

	void ask_to_stop();

	virtual void start();
	void stop();

	void register_protocol(const uint16_t ether_type, network_layer *const p);

	network_layer *get_protocol(const uint16_t p);

	virtual bool transmit_packet(const any_addr & dest_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size) = 0;

	int get_max_packet_size() const { return mtu_size - 14 /* 14 = size of Ethernet header */; }

	std::string to_str() const { return name; }

	virtual any_addr::addr_family get_phys_type() = 0;

	virtual void operator()() = 0;
};
