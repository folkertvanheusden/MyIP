// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "sip.h"
#include "udp.h"
#include "utils.h"


sip::sip(stats *const s, udp *const u) : u(u)
{
	th = new std::thread(std::ref(*this));
}

sip::~sip()
{
	stop_flag = true;
	th->join();
	delete th;
}

void sip::input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p)
{
	dolog(info, "SIP packet from [%s]:%u: %s\n", src_ip.to_str().c_str(), src_port, (const char *)p->get_data());
}

void sip::operator()()
{
	set_thread_name("myip-sip");

	while(!stop_flag) {
		myusleep(500000);

		// FIXME something
	}
}
