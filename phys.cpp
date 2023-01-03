// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <algorithm>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "buffer_out.h"
#include "log.h"
#include "packet.h"
#include "phys.h"
#include "str.h"


phys::phys(const size_t dev_index, stats *const s, const std::string & name) :
	dev_index(dev_index),  // used for SNMP
	name(name)
{
	// 1.3.6.1.4.1.57850.1.8: physical device
	phys_recv_frame = s->register_stat("phys_recv_frame", "1.3.6.1.4.1.57850.1.8.1");
	phys_invl_frame = s->register_stat("phys_invl_frame", "1.3.6.1.4.1.57850.1.8.2");
	phys_ign_frame  = s->register_stat("phys_ign_frame",  "1.3.6.1.4.1.57850.1.8.3");

	phys_ifInOctets     = s->register_stat("phys_ifInOctets",     myformat("1.3.6.1.2.1.2.2.1.10.%zu", dev_index), snmp_integer::si_counter32);
	phys_ifHCInOctets   = s->register_stat("phys_ifHCInOctets",   myformat("1.3.6.1.2.1.31.1.1.1.6.%zu", dev_index), snmp_integer::si_counter64);
	phys_ifInUcastPkts  = s->register_stat("phys_ifInUcastPkts",  myformat("1.3.6.1.2.1.2.2.1.11.%zu", dev_index), snmp_integer::si_counter32);
	phys_ifOutOctets    = s->register_stat("phys_ifOutOctets",    myformat("1.3.6.1.2.1.2.2.1.16.%zu", dev_index), snmp_integer::si_counter32);
	phys_ifHCOutOctets  = s->register_stat("phys_ifHCOutOctets",  myformat("1.3.6.1.2.1.31.1.1.1.10.%zu", dev_index), snmp_integer::si_counter64);
	phys_ifOutUcastPkts = s->register_stat("phys_ifOutUcastPkts", myformat("1.3.6.1.2.1.2.2.1.17.%zu", dev_index), snmp_integer::si_counter32);

	// MTU size for Ethernet
	mtu_size = 1500;
}

phys::~phys()
{
	stop_flag = true;

	th->join();
	delete th;
}

void phys::start()
{
}

void phys::ask_to_stop()
{
	stop_flag = true;
}

void phys::start_pcap(const std::string & pcap_file, const bool in, const bool out)
{
	if (pcap_fd != -1)
		error_exit(false, "phys: pcap already running");

	pcap_fd = open(pcap_file.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (pcap_fd == -1)
		error_exit(true, "phys: canot create \"%s\"", pcap_file.c_str());

	buffer_out header;
	header.add_net_long(0xA1B23C4D);  // magic
	header.add_net_short(2);  // major
	header.add_net_short(4);  // minor
	header.add_net_long(0);  // reserved1
	header.add_net_long(0);  // reserved2
	header.add_net_long(mtu_size);  // snaplen
	header.add_net_long(1);  // linktype

	pcap_write_incoming = in;
	pcap_write_outgoing = out;

	if (WRITE(pcap_fd, header.get_content(), header.get_size()) != header.get_size())
		DOLOG(ll_error, "phys: cannot write to pcap file (header)\n");
}

void phys::stop_pcap()
{
	if (pcap_fd != -1) {
		close(pcap_fd);

		pcap_fd = -1;
	}
}

void phys::pcap_write_packet(const timespec & ts, const uint8_t *const data, const size_t n)
{
	buffer_out record;
	record.add_net_long(ts.tv_sec); // timestamp seconds
	record.add_net_long(ts.tv_nsec); // timestamp nano seconds
	record.add_net_long(n);  // captured packet length
	record.add_net_long(n);  // original packet length
	record.add_buffer(data, n);

	if (WRITE(pcap_fd, record.get_content(), record.get_size()) != record.get_size())
		DOLOG(ll_error, "phys: cannot write to pcap file (record)\n");
}

void phys::pcap_write_packet_incoming(const timespec & ts, const uint8_t *const data, const size_t n)
{
	if (pcap_write_incoming)
		pcap_write_packet(ts, data, n);
}

void phys::pcap_write_packet_outgoing(const timespec & ts, const uint8_t *const data, const size_t n)
{
	if (pcap_write_outgoing)
		pcap_write_packet(ts, data, n);
}

void phys::register_protocol(const uint16_t ether_type, network_layer *const p)
{
	prot_map.insert({ ether_type, p });

	p->register_default_phys(this);
}

network_layer *phys::get_protocol(const uint16_t protocol)
{
	auto it = prot_map.find(protocol);
	if (it == prot_map.end())
		return nullptr;

	return it->second;
}

bool phys::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size)
{
	return false;
}

void phys::operator()()
{
	DOLOG(ll_info, "phys: thread stopped\n");
}
