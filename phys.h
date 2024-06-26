// (C) 2020-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <map>
#include <pcap.h>
#include <string>
#include <thread>

#include "any_addr.h"
#include "network_layer.h"
#include "stats.h"


#ifndef SIOCGSTAMPNS_OLD
#define SIOCGSTAMPNS_OLD SIOCGSTAMPNS
#endif

class router;

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

	router   *const r;
	std::map<uint16_t, network_layer *> prot_map;

	const size_t dev_index     { 0 };

	const std::string name;

	any_addr  my_mac;

	bool      SIOCGSTAMPNS_OLD_error_emitted = false;

	std::mutex pcap_lock;
	pcap_t   *ph                  { nullptr };
	pcap_dumper_t *pdh            { nullptr };
	bool      pcap_write_incoming { false   };
	bool      pcap_write_outgoing { false   };

	void pcap_write_packet_incoming(const timespec & ts, const uint8_t *const data, const size_t n);
	void pcap_write_packet_outgoing(const timespec & ts, const uint8_t *const data, const size_t n);

public:
	phys(const size_t dev_index, stats *const s, const std::string & name, router *const r);
	phys(const phys &) = delete;
	virtual ~phys();

	void ask_to_stop();

	void start_pcap(const std::string & pcap_file, const bool in, const bool out, const uint32_t link_type);
	void stop_pcap();

	virtual void start();
	void stop();

	timespec gen_packet_timestamp(const int fd);

	void register_protocol(const uint16_t ether_type, network_layer *const p);

	any_addr get_local_mac() const { return my_mac; }

	network_layer *get_protocol(const uint16_t p);

	virtual bool transmit_packet(const any_addr & dest_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size) = 0;

	int get_max_packet_size() const { return mtu_size - 14 /* 14 = size of Ethernet header */; }

	std::string to_str() const { return name; }

	virtual any_addr::addr_family get_phys_type() = 0;

	virtual void operator()() = 0;
};
