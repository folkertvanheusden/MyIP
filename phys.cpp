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

#include "log.h"
#include "phys.h"
#include "packet.h"
#include "utils.h"


phys::phys(const size_t dev_index, stats *const s) :
	dev_index(dev_index)  // used for SNMP
{
	// 1.3.6.1.2.1.4.57850.1.8: physical device
	phys_recv_frame = s->register_stat("phys_recv_frame", "1.3.6.1.2.1.4.57850.1.8.1");
	phys_invl_frame = s->register_stat("phys_invl_frame", "1.3.6.1.2.1.4.57850.1.8.2");
	phys_ign_frame  = s->register_stat("phys_ign_frame",  "1.3.6.1.2.1.4.57850.1.8.3");

	phys_ifInOctets     = s->register_stat("phys_ifInOctets",     myformat("1.3.6.1.2.1.2.2.1.10.%zu", dev_index), snmp_integer::si_counter32);
	phys_ifHCInOctets   = s->register_stat("phys_ifHCInOctets",   myformat("1.3.6.1.2.1.31.1.1.1.6.%zu", dev_index), snmp_integer::si_counter64);
	phys_ifInUcastPkts  = s->register_stat("phys_ifInUcastPkts",  myformat("1.3.6.1.2.1.2.2.1.11.%zu", dev_index), snmp_integer::si_counter32);
	phys_ifOutOctets    = s->register_stat("phys_ifOutOctets",    myformat("1.3.6.1.2.1.2.2.1.16.%zu", dev_index), snmp_integer::si_counter32);
	phys_ifHCOutOctets  = s->register_stat("phys_ifHCOutOctets",  myformat("1.3.6.1.2.1.31.1.1.1.10.%zu", dev_index), snmp_integer::si_counter64);
	phys_ifOutUcastPkts = s->register_stat("phys_ifOutUcastPkts", myformat("1.3.6.1.2.1.2.2.1.17.%zu", dev_index), snmp_integer::si_counter32);

	// MTU size for Ethernet
	mtu_size = 1500;
	DOLOG(debug, "phys: MTU size: %d\n", mtu_size);
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

void phys::register_protocol(const uint16_t ether_type, protocol *const p)
{
	prot_map.insert({ ether_type, p });

	p->register_default_phys(this);
}

protocol *phys::get_protocol(const uint16_t p)
{
	auto it = prot_map.find(p);
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
	DOLOG(info, "phys: thread stopped\n");
}
