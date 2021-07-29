// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under AGPL v3.0
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#include "stats.h"
#include "phys.h"
#include "arp.h"
#include "ipv4.h"
#include "icmp.h"
#include "udp.h"
#include "ntp.h"
#include "tcp.h"
#include "tcp_udp_fw.h"
#include "http.h"
#include "vnc.h"
#include "utils.h"

void ss(int s)
{
}

int main(int argc, char *argv[])
{
	chdir("/tmp");

	signal(SIGINT, ss);

	stats s(4096);

	phys *dev = new phys(&s, "myip");

	// change 1000 to UID to run under
	if (setuid(1000) == -1) {
		perror("setuid");
		return 1;
	}

	dolog("*** START ***\n");

	constexpr uint8_t myip[] = { 192, 168, 3, 2 }; // change this
	constexpr uint8_t mymac[] = { 0x52, 0x34, 0x84, 0x16, 0x44, 0x22 };

	arp *a = new arp(&s, mymac, myip);
	dev->register_protocol(0x0806, a);

	ipv4 *ipv4_instance = new ipv4(&s, a, myip);

	icmp *icmp_ = new icmp(&s);
	ipv4_instance->register_protocol(0x01, icmp_);
	// rather ugly but that's how IP works
	ipv4_instance->register_icmp(icmp_);

	tcp *t = new tcp(&s, icmp_);
	ipv4_instance->register_protocol(0x06, t);
	udp *u = new udp(&s, icmp_);
	ipv4_instance->register_protocol(0x11, u);

	dev->register_protocol(0x0800, ipv4_instance);

	constexpr uint8_t upstream_ntp_server[] = { 192, 168, 64, 1 }; // change this

	tcp_port_handler_t http_handler = http_get_handler("/home/folkert/http_access.log"); // change this
	t->add_handler(80, http_handler);

	tcp_port_handler_t vnc_handler = vnc_get_handler();
	t->add_handler(5900, vnc_handler);

	ntp *ntp_ = new ntp(&s, u, upstream_ntp_server, true);
	u->add_handler(123, std::bind(&ntp::input, ntp_, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));

	// something that silently drops packet for a port
	tcp_udp_fw *firewall = new tcp_udp_fw(&s, u);
	u->add_handler(22, std::bind(&tcp_udp_fw::input, firewall, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));

	getchar();

	dolog(" *** TERMINATING ***\n");
	dolog("THIS IS THE END\n");

	exit(0); // FIXME debug

	delete dev;
	delete a;
	delete ipv4_instance;
	delete icmp_;
	delete u;
	delete ntp_;
	delete t;
	delete firewall;

	return 0;
}
