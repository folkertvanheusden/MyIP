// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <iniparser/iniparser.h>
#include <signal.h>
#include <stdio.h>
#include <string>
#include <unistd.h>
#include <vector>
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

void parse_ip_address(const char *ip_str, uint8_t *const p)
{
	std::vector<std::string> *ip_parts = split(ip_str, ".");

	if (ip_parts->size() != 4) {
		fprintf(stderr, "An IPv4 address consists of 4 numbers\n");
		exit(1);
	}

	for(int i=0; i<4; i++)
		p[i] = atoi(ip_parts->at(i).c_str());
}

void parse_mac_address(const char *mac_str, uint8_t *const mymac)
{
	std::vector<std::string> *mac_parts = split(mac_str, ":");

	if (mac_parts->size() != 6) {
		fprintf(stderr, "An Ethernet MAC-address consists of 6 (hex-)values\n");
		exit(1);
	}

	for(int i=0; i<6; i++)
		mymac[i] = strtol(mac_parts->at(i).c_str(), nullptr, 16);
}

void ss(int s)
{
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "File name of configuration ini file missing\n");
		return 1;
	}

	dictionary *ini = iniparser_load(argv[1]);

	chdir(iniparser_getstring(ini, "cfg:chdir-path", "/tmp"));

	signal(SIGINT, ss);

	stats s(4096);

	phys *dev = new phys(&s, iniparser_getstring(ini, "cfg:dev-name", "myip"));

	// change 1000 to UID to run under
	if (setuid(iniparser_getint(ini, "cfg:run-as", 1000)) == -1) {
		perror("setuid");
		return 1;
	}

	dolog("*** START ***\n");

	const char *mac_str = iniparser_getstring(ini, "cfg:mac-address", "52:34:84:16:44:22");
	uint8_t mymac[6] { 0 };
	parse_mac_address(mac_str, mymac);

	printf("Will listen on MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", mymac[0], mymac[1], mymac[2], mymac[3], mymac[4], mymac[5]);

	const char *ip_str = iniparser_getstring(ini, "cfg:ip-address", "192.168.3.2");
	uint8_t myip[4] { 0 };
	parse_ip_address(ip_str, myip);

	printf("Will listen on IPv4 address: %d.%d.%d.%d\n", myip[0], myip[1], myip[2], myip[3]);

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

	const char *ntp_ip_str = iniparser_getstring(ini, "cfg:ntp-ip-address", "192.168.64.1");
	uint8_t upstream_ntp_server[4] { 0 };
	parse_ip_address(ntp_ip_str, upstream_ntp_server);

	const char *web_root = iniparser_getstring(ini, "cfg:web-root", "/home/folkert/www");
	const char *http_logfile = iniparser_getstring(ini, "cfg:web-logfile", "/home/folkert/http_access.log");

	tcp_port_handler_t http_handler = http_get_handler(web_root, http_logfile);
	t->add_handler(80, http_handler);

	tcp_port_handler_t vnc_handler = vnc_get_handler();
	t->add_handler(5900, vnc_handler);

	ntp *ntp_ = new ntp(&s, u, upstream_ntp_server, true);
	u->add_handler(123, std::bind(&ntp::input, ntp_, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));

	// something that silently drops packet for a port
	tcp_udp_fw *firewall = new tcp_udp_fw(&s, u);
	u->add_handler(22, std::bind(&tcp_udp_fw::input, firewall, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));

	dolog("*** STARTED ***\n");
	printf("*** STARTED ***\n");
	printf("Press enter to terminate\n");

	getchar();

	dolog(" *** TERMINATING ***\n");

	delete dev;
	delete a;
	delete ipv4_instance;
	delete icmp_;
	delete u;
	delete ntp_;
	delete t;
	delete firewall;

	dolog("THIS IS THE END\n");

	return 0;
}
