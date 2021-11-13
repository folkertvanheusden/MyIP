// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <iniparser/iniparser.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <sys/types.h>

#include "any_addr.h"
#include "stats.h"
#include "phys.h"
#include "arp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "icmp.h"
#include "icmp6.h"
#include "arp.h"
#include "ndp.h"
#include "sip.h"
#include "ntp.h"
#include "syslog.h"
#include "snmp.h"
#include "tcp.h"
#include "http.h"
#include "vnc.h"
#include "mqtt.h"
#include "utils.h"

void free_handler(const tcp_port_handler_t & tph)
{
	delete tph.pd;
}

log_level_t parse_ll(const std::string & ll)
{
	if (ll == "debug")
		return debug;

	if (ll == "info")
		return info;

	if (ll == "warning")
		return warning;

	if (ll == "error")
		return error;

	fprintf(stderr, "Log-level \"%s\" not understood\n", ll.c_str());

	return debug;
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

	signal(SIGCHLD, SIG_IGN);

	dictionary *ini = iniparser_load(argv[1]);

	std::string llf = iniparser_getstring(ini, "cfg:log_level_file", "debug");
	std::string lls = iniparser_getstring(ini, "cfg:log_level_screen", "warning");

	setlog(iniparser_getstring(ini, "cfg:logfile", "/tmp/myip.log"), parse_ll(llf), parse_ll(lls));

	dolog(info, "*** START ***\n");

	if (chdir(iniparser_getstring(ini, "cfg:chdir-path", "/tmp")) == -1) {
		dolog(error, "chdir: %s", strerror(errno));
		return 1;
	}

	signal(SIGINT, ss);

	stats s(4096);

	const int uid = iniparser_getint(ini, "cfg:run-as", 1000);  // uid
	const int gid = iniparser_getint(ini, "cfg:run-in", 1000);  // gid

	setloguid(uid, gid);

	phys *dev = new phys(&s, iniparser_getstring(ini, "cfg:dev-name", "myip"), uid, gid);

	if (setgid(gid) == -1) {
		dolog(error, "setgid: %s", strerror(errno));
		return 1;
	}

	if (setuid(uid) == -1) {
		dolog(error, "setuid: %s", strerror(errno));
		return 1;
	}

	const char *mac_str = iniparser_getstring(ini, "cfg:mac-address", "52:34:84:16:44:22");
	any_addr mymac = parse_address(mac_str, 6, ":", 16);

	printf("Will listen on MAC address: %s\n", mymac.to_str().c_str());

	const char *ip_str = iniparser_getstring(ini, "cfg:ip-address", "192.168.3.2");
	any_addr myip = parse_address(ip_str, 4, ".", 10);

	printf("Will listen on IPv4 address: %s\n", myip.to_str().c_str());

	const char *gw_mac_str = iniparser_getstring(ini, "cfg:gateway-mac-address", "42:20:16:2b:6f:9b");
	any_addr gw_mac = parse_address(gw_mac_str, 6, ":", 16);

	arp *a = new arp(&s, mymac, myip, gw_mac);
	dev->register_protocol(0x0806, a);

	ipv4 *ipv4_instance = new ipv4(&s, a, myip);

	icmp *icmp_ = new icmp(&s);
	ipv4_instance->register_protocol(0x01, icmp_);
	// rather ugly but that's how IP works
	ipv4_instance->register_icmp(icmp_);

	tcp *t = new tcp(&s);
	ipv4_instance->register_protocol(0x06, t);

	dev->register_protocol(0x0800, ipv4_instance);

	const char *ntp_ip_str = iniparser_getstring(ini, "cfg:ntp-ip-address", "192.168.64.1");
	any_addr upstream_ntp_server = parse_address(ntp_ip_str, 4, ".", 10);

	const char *web_root = iniparser_getstring(ini, "cfg:web-root", "/home/folkert/www");
	const char *http_logfile = iniparser_getstring(ini, "cfg:web-logfile", "/home/folkert/http_access.log");

	tcp_port_handler_t http_handler = http_get_handler(&s, web_root, http_logfile);
	t->add_handler(80, http_handler);

	tcp_port_handler_t vnc_handler = vnc_get_handler(&s);
	t->add_handler(5900, vnc_handler);

	tcp_port_handler_t mqtt_handler = mqtt_get_handler(&s);
	t->add_handler(1883, mqtt_handler);


	std::string run_at_started = iniparser_getstring(ini, "cfg:ifup", "");
	if (run_at_started.empty() == false)
		run(run_at_started);

	dolog(debug, "*** STARTED ***\n");
	printf("*** STARTED ***\n");
	printf("Press enter to terminate\n");

	getchar();

	dolog(info, " *** TERMINATING ***\n");
	fprintf(stderr, "terminating\n");

	std::string run_at_shutdown = iniparser_getstring(ini, "cfg:ifdown", "");
	if (run_at_shutdown.empty() == false)
		run(run_at_shutdown);

	free_handler(http_handler);

	free_handler(vnc_handler);


	if (vnc_handler.deinit)
		vnc_handler.deinit();

	if (http_handler.deinit)
		http_handler.deinit();

	dev->stop();

	delete icmp_;
	delete t;
	delete ipv4_instance;
	delete a;
	delete dev;

	dolog(info, "THIS IS THE END\n");

	closelog();

	iniparser_freedict(ini);

	return 0;
}
