// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "syslog.h"
#include "udp.h"
#include "utils.h"


syslog_srv::syslog_srv(stats *const s)
{
	// 1.3.6.1.2.1.4.57850.1.6: syslog
	syslog_srv_requests = s->register_stat("syslog_srv_requests", "1.3.6.1.2.1.4.57850.1.6.1");
}

syslog_srv::~syslog_srv()
{
	stop_flag = true;
}

void syslog_srv::input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, void *const pd)
{
	stats_inc_counter(syslog_srv_requests);

	auto pl = p->get_payload();

	if (pl.second == 0) {
		dolog(info, "SYSLOG: empty packet from [%s]:%u\n", src_ip.to_str().c_str(), src_port);
		return;
	}

	std::string pl_str = std::string((const char *)pl.first, pl.second);

	dolog(info, "SYSLOG: \"%s\" from [%s]:%d\n", pl_str.c_str(), src_ip.to_str().c_str(), src_port);
}
