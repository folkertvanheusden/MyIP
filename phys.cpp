// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <algorithm>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "buffer_out.h"
#include "hash.h"
#include "log.h"
#include "packet.h"
#include "phys.h"
#include "str.h"


phys::phys(const size_t dev_index, stats *const s, const std::string & name, router *const r) :
	r(r),
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
	stop_pcap();

	stop_flag = true;

	if (th) {
		th->join();
		delete th;
	}
}

void phys::start()
{
}

void phys::ask_to_stop()
{
	stop_flag = true;
}

timespec phys::gen_packet_timestamp(const int fd)
{
	timespec ts { 0, 0 };

	if (ioctl(fd, SIOCGSTAMPNS_OLD, &ts) == -1) {
		if (SIOCGSTAMPNS_OLD_error_emitted == false) {
			CDOLOG(ll_info, "[phys]", "ioctl(SIOCGSTAMPNS_OLD) failed: %s\n", strerror(errno));

			SIOCGSTAMPNS_OLD_error_emitted = true;
		}

		if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
			CDOLOG(ll_warning, "[phys]", "clock_gettime failed: %s", strerror(errno));
	}

	return ts;
}

void phys::start_pcap(const std::string & pcap_file, const bool in, const bool out, const uint32_t link_type)
{
	std::unique_lock<std::mutex> lck(pcap_lock);

	if (!ph)
		ph = pcap_open_dead_with_tstamp_precision(link_type, 65535, PCAP_TSTAMP_PRECISION_MICRO);

	pcap_write_incoming = in;
	pcap_write_outgoing = out;

	if (pdh)
		CDOLOG(ll_error, "[phys]", "pcap already running\n");
	else if (in || out) {
		std::string temp = myformat(pcap_file.c_str(), md5hex(myformat("%s-%zu", name.c_str(), dev_index)).substr(0, 4).c_str());
		pdh = pcap_dump_open(ph, temp.c_str());
		if (!pdh)
			error_exit(false, "pcap_dump_open(%s) failed: %s", temp.c_str(), pcap_geterr(ph));
	}
}

void phys::stop_pcap()
{
	if (pdh) {
		std::unique_lock<std::mutex> lck(pcap_lock);
		pcap_dump_close(pdh);
	}
}

void phys::pcap_write_packet_incoming(const timespec & ts, const uint8_t *const data, const size_t n)
{
	if (pcap_write_incoming) {
		pcap_pkthdr header { 0 };
		header.ts.tv_sec  = ts.tv_sec;
		header.ts.tv_usec = ts.tv_nsec / 1000;
		header.len        = header.caplen = n;

		std::unique_lock<std::mutex> lck(pcap_lock);
		pcap_dump(reinterpret_cast<u_char *>(pdh), &header, data);
	}
}

void phys::pcap_write_packet_outgoing(const timespec & ts, const uint8_t *const data, const size_t n)
{
	if (pcap_write_outgoing) {
		pcap_pkthdr header { 0 };
		header.ts.tv_sec  = ts.tv_sec;
		header.ts.tv_usec = ts.tv_nsec / 1000;
		header.len        = header.caplen = n;

		std::unique_lock<std::mutex> lck(pcap_lock);
		pcap_dump(reinterpret_cast<u_char *>(pdh), &header, data);
	}
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
	CDOLOG(ll_info, "[phys]", "thread stopped\n");
}
