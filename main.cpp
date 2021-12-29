// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <errno.h>
#include <libconfig.h++>
#include <signal.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <sys/types.h>

#include "any_addr.h"
#include "stats.h"
#include "phys_ethernet.h"
#include "phys_slip.h"
#include "arp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "icmp.h"
#include "icmp6.h"
#include "arp.h"
#include "ndp.h"
#include "sip.h"
#include "udp.h"
#include "ntp.h"
#include "syslog.h"
#include "snmp.h"
#include "tcp.h"
#include "tcp_udp_fw.h"
#include "http.h"
#include "vnc.h"
#include "mqtt.h"
#include "utils.h"

void error_exit(const bool se, const char *format, ...)
{
	int e = errno;
	va_list ap;

	va_start(ap, format);
	char *temp = NULL;
	if (vasprintf(&temp, format, ap) == -1)
		puts(format);  // last resort
	va_end(ap);

	fprintf(stderr, "%s\n", temp);
	dolog(error, "%s\n", temp);

	if (se && e) {
		fprintf(stderr, "errno: %d (%s)\n", e, strerror(e));
		dolog(error, "errno: %d (%s)\n", e, strerror(e));
	}

	free(temp);

	exit(EXIT_FAILURE);
}

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

std::string cfg_str(const libconfig::Setting & cfg, const std::string & key, const char *descr, const bool optional, const std::string & def)
{
	try {
		return (const char *)cfg.lookup(key.c_str());
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		if (!optional)
			error_exit(false, "\"%s\" not found (%s)", key.c_str(), descr);
	}

	dolog(info, "\"%s\" not found (%s), assuming default (%s)\n", key.c_str(), descr, def.c_str());

	return def; // field is optional
}

int cfg_int(const libconfig::Setting & cfg, const std::string & key, const char *descr, const bool optional, const int def=-1)
{
	int v = def;

	try {
		v = cfg.lookup(key.c_str());
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		if (!optional)
			error_exit(false, "\"%s\" not found (%s)", key.c_str(), descr);

		dolog(info, "\"%s\" not found (%s), assuming default (%d)\n", key.c_str(), descr, def);
	}

	catch(const libconfig::SettingTypeException & ste) {
		error_exit(false, "Expected an int value for \"%s\" (%s) at line %d but got something else", key.c_str(), descr, cfg.getSourceLine());
	}

	return v;
}

int cfg_bool(const libconfig::Setting & cfg, const char *const key, const char *descr, const bool optional, const bool def=false)
{
	bool v = def;

	try {
		v = cfg.lookup(key);
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		if (!optional)
			error_exit(false, "\"%s\" not found (%s)", key, descr);

		dolog(info, "\"%s\" not found (%s), assuming default (%d)\n", key, descr, def);
	}
	catch(const libconfig::SettingTypeException & ste) {
		error_exit(false, "Expected a boolean value for \"%s\" (%s) but got something else", key, descr);
	}

	return v;
}

void register_tcp_service(std::vector<phys *> *const devs, tcp_port_handler_t & tph, const int port)
{
	for(auto & dev : *devs) {
		ipv4 *i4 = (ipv4 *)dev->get_protocol(0x0800);
		if (!i4)
			continue;

		tcp *const t4 = (tcp *)i4->get_ip_protocol(0x06);
		if (!t4)
			continue;

		t4->add_handler(port, tph);

		ipv6 *i6 = (ipv6 *)dev->get_protocol(0x86dd);
		if (!i6)
			continue;

		tcp *const t6 = (tcp *)i6->get_ip_protocol(0x06);
		if (!t6)
			continue;

		t6->add_handler(port, tph);
	}
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "File name of configuration cfg-file missing\n");
		return 1;
	}

	signal(SIGCHLD, SIG_IGN);

	libconfig::Config lc_cfg;

	try {
		lc_cfg.readFile(argv[1]);
	}
	catch(const libconfig::FileIOException &fioex) {
		fprintf(stderr, "I/O error while reading configuration file %s\n", argv[1]);
		return 1;
	}
	catch(const libconfig::ParseException &pex) {
		fprintf(stderr, "Configuration file %s parse error at line %d: %s\n", pex.getFile(), pex.getLine(), pex.getError());
		return 1;
	}

	const libconfig::Setting & root = lc_cfg.getRoot();

	/// logging
	{
		const libconfig::Setting & logging = root.lookup("logging");

		std::string llf = cfg_str(logging, "level_file", "log level file", true, "debug");
		std::string lls = cfg_str(logging, "level_screen", "log level screen", true, "debug");

		std::string log_file = cfg_str(logging, "file", "log file", true, "/tmp/myip.log");

		setlog(log_file.c_str(), parse_ll(llf), parse_ll(lls));
	}

	dolog(info, "*** START ***\n");

	signal(SIGINT, ss);

	stats s(8192);

	/// environment
	int uid = 1000, gid = 1000;
	{
		const libconfig::Setting & environment = root.lookup("environment");

		int uid = cfg_int(environment, "run-as", "user to run as", true, 1000);
		int gid = cfg_int(environment, "run-in", "group to run in", true, 1000);
		setloguid(uid, gid);

		std::string chdir_path = cfg_str(environment, "chdir-path", "directory to chdir to", true, "/tmp");

		if (chdir(chdir_path.c_str()) == -1) {
			dolog(error, "chdir: %s", strerror(errno));
			return 1;
		}
	}

	// used for clean-up
	std::vector<protocol *> protocols;
	std::vector<ip_protocol *> ip_protocols;

	/// network interfaces
	const libconfig::Setting &interfaces = root["interfaces"];
	size_t n_interfaces = interfaces.getLength();

	std::vector<phys *> devs;

	for(size_t i=0; i<n_interfaces; i++) {
		const libconfig::Setting &interface = interfaces[i];

		std::string type = cfg_str(interface, "type", "network interface type (e.g. \"ethernet\" or \"slip\")", true, "ethernet");

		std::string mac = cfg_str(interface, "mac-address", "MAC address", true, "52:34:84:16:44:22");
		any_addr my_mac = parse_address(mac.c_str(), 6, ":", 16);

		printf("%zu] Will listen on MAC address: %s\n", i, my_mac.to_str().c_str());

		phys *dev = nullptr;

		if (type == "ethernet") {
			std::string dev_name = cfg_str(interface, "dev-name", "device name", true, "myip");

			dev = new phys_ethernet(&s, dev_name, uid, gid);
		}
		else if (type == "slip") {
			std::string dev_name = cfg_str(interface, "serial-dev", "serial port device node", false, "/dev/ttyS0");

			int baudrate = cfg_int(interface, "baudrate", "serial port baudrate", true, 115200);
			int bps_setting = 0;
			if (baudrate == 9600)
				bps_setting = B9600;
			else if (baudrate == 115200)
				bps_setting = B115200;
			else
				error_exit(false, "\"%d\" cannot be configured", baudrate);

			dev = new phys_slip(&s, dev_name, bps_setting, my_mac);
		}
		else
			error_exit(false, "\"%s\" is an unknown network interface type", type.c_str());

		devs.push_back(dev);

		// ipv4
		try {
			const libconfig::Setting & ipv4_ = interface.lookup("ipv4");

			std::string ma_str = cfg_str(ipv4_, "my-address", "IPv4 address", false, "192.168.3.2");
			any_addr my_address = parse_address(ma_str.c_str(), 4, ".", 10);

			std::string gw_str = cfg_str(ipv4_, "gateway-mac-address", "default gateway MAC address", false, "42:20:16:2b:6f:9b");
			any_addr gw_mac = parse_address(gw_str.c_str(), 6, ":", 16);

			printf("%zu] Will listen on IPv4 address: %s\n", i, my_address.to_str().c_str());

			arp *a = new arp(&s, my_mac, my_address, gw_mac);
			a->add_static_entry(dev, my_mac, my_address);
			dev->register_protocol(0x0806, a);

			ipv4 *ipv4_instance = new ipv4(&s, a, my_address);
			protocols.push_back(ipv4_instance);

			bool use_icmp = cfg_bool(ipv4_, "use-icmp", "if to enable icmp", true, true);
			icmp *icmp_ = nullptr;
			if (use_icmp) {
				icmp_ = new icmp(&s);

				ipv4_instance->register_protocol(0x01, icmp_);
				// rather ugly but that's how IP works
				ipv4_instance->register_icmp(icmp_);

				ip_protocols.push_back(icmp_);
			}

			bool use_tcp = cfg_bool(ipv4_, "use-tcp", "wether to enable tcp", true, true);
			if (use_tcp) {
				tcp *t = new tcp(&s);
				ipv4_instance->register_protocol(0x06, t);

				ip_protocols.push_back(t);
			}

			bool use_udp = cfg_bool(ipv4_, "use-udp", "wether to enable udp", true, true);
			if (use_udp) {
				udp *u = new udp(&s, icmp_);
				ipv4_instance->register_protocol(0x11, u);

				ip_protocols.push_back(u);
			}

			dev->register_protocol(0x0800, ipv4_instance);

			protocols.push_back(a);
		}
		catch(const libconfig::SettingNotFoundException &nfex) {
			// just fine
		}

		// ipv6
		try {
			const libconfig::Setting & ipv6_ = interface.lookup("ipv6");

			std::string ma_str = cfg_str(ipv6_, "my-address", "IPv6 address", false, "2001:980:c324:4242:f588:20f4:4d4e:7c2d");
			any_addr my_ip6 = parse_address(ma_str.c_str(), 16, ":", 16);

			printf("%zu] Will listen on IPv6 address: %s\n", i, my_ip6.to_str().c_str());

			ndp *ndp_ = new ndp(&s);
			ndp_->add_static_entry(dev, my_mac, my_ip6);
			protocols.push_back(ndp_);

			ipv6 *ipv6_instance = new ipv6(&s, ndp_, my_ip6);
			protocols.push_back(ipv6_instance);

			dev->register_protocol(0x86dd, ipv6_instance);

			bool use_icmp = cfg_bool(ipv6_, "use-icmp", "wether to enable icmp", true, true);
			icmp6 *icmp6_ = nullptr;
			if (use_icmp) {
				icmp6_ = new icmp6(&s, my_mac, my_ip6);
				ip_protocols.push_back(icmp6_);

				ipv6_instance->register_protocol(0x3a, icmp6_);  // 58
				ipv6_instance->register_icmp(icmp6_);
			}

			bool use_tcp = cfg_bool(ipv6_, "use-tcp", "wether to enable tcp", true, true);
			if (use_tcp) {
				tcp *t6 = new tcp(&s);
				ipv6_instance->register_protocol(0x06, t6);  // TCP
				ip_protocols.push_back(t6);
			}

			bool use_udp = cfg_bool(ipv6_, "use-udp", "wether to enable udp", true, true);
			if (use_udp) {
				udp *u = new udp(&s, icmp6_);
				ipv6_instance->register_protocol(0x11, u);

				ip_protocols.push_back(u);
			}
		}
		catch(const libconfig::SettingNotFoundException &nfex) {
			// just fine
		}
	}

	if (setgid(gid) == -1) {
		dolog(error, "setgid: %s", strerror(errno));
		return 1;
	}

	if (setuid(uid) == -1) {
		dolog(error, "setuid: %s", strerror(errno));
		return 1;
	}

	// NTP
	try {
		const libconfig::Setting & s_ntp = root.lookup("ntp");

		std::string ntp_u_ip_str = cfg_str(s_ntp, "upstream-ip-address", "upstream NTP server", false, "");
		any_addr upstream_ntp_server = parse_address(ntp_u_ip_str.c_str(), 4, ".", 10);

		int port = cfg_int(s_ntp, "port", "udp port to listen on", true, 123);

		for(auto & dev : devs) {
			ipv4 *i4 = (ipv4 *)dev->get_protocol(0x0800);
			if (!i4)
				continue;

			udp *const u = (udp *)i4->get_ip_protocol(0x11);
			if (!u)
				continue;

			ntp *ntp_ = new ntp(&s, u, i4->get_addr(), upstream_ntp_server, true);

			u->add_handler(port, std::bind(&ntp::input, ntp_, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), nullptr);
		}
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		// just fine
	}

	// HTTP
	try {
		const libconfig::Setting & s_http = root.lookup("http");

		std::string web_root = cfg_str(s_http, "web-root", "HTTP server files root", false, "");
		std::string web_logfile = cfg_str(s_http, "web-logfile", "HTTP server logfile", false, "");

		int port = cfg_int(s_http, "port", "tcp port to listen on", true, 80);

		tcp_port_handler_t http_handler = http_get_handler(&s, web_root, web_logfile);

		register_tcp_service(&devs, http_handler, port);
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		// just fine
	}

	// VNC
	try {
		const libconfig::Setting & s_vnc = root.lookup("vnc");

		int port = cfg_int(s_vnc, "port", "tcp port to listen on", true, 5900);

		tcp_port_handler_t vnc_handler = vnc_get_handler(&s);

		register_tcp_service(&devs, vnc_handler, port);
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		// just fine
	}

	// MQTT
	try {
		const libconfig::Setting & s_mqtt = root.lookup("mqtt");

		int port = cfg_int(s_mqtt, "port", "tcp port to listen on", true, 1883);

		tcp_port_handler_t mqtt_handler = mqtt_get_handler(&s);

		register_tcp_service(&devs, mqtt_handler, port);
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		// just fine
	}

	// SIP
	try {
		const libconfig::Setting & s_sip = root.lookup("sip");

		std::string sample = cfg_str(s_sip, "sample", "audio sample to play", false, "");
		std::string mb_path = cfg_str(s_sip, "mb-path", "where to store audio", false, "");
		std::string mb_recv_script = cfg_str(s_sip, "mb-recv-script", "script to invoke on received audio", true, "");
		std::string upstream_sip_server = cfg_str(s_sip, "upstream-sip-server", "upstream SIP server", false, "");
		std::string upstream_sip_user = cfg_str(s_sip, "upstream-sip-user", "upstream SIP user", false, "");
		std::string upstream_sip_password = cfg_str(s_sip, "upstream-sip-password", "upstream SIP password", false, "");
		int sip_register_interval = cfg_int(s_sip, "sip-register-interval", "SIP upstream registesr interval", true, 450);

		int port = cfg_int(s_sip, "port", "udp port to listen on", true, 123);

		for(auto & dev : devs) {
			ipv4 *i4 = (ipv4 *)dev->get_protocol(0x0800);
			if (!i4)
				continue;

			udp *const u = (udp *)i4->get_ip_protocol(0x11);
			if (!u)
				continue;

			sip *sip_ = new sip(&s, u, sample, mb_path, mb_recv_script, upstream_sip_server, upstream_sip_user, upstream_sip_password, i4->get_addr(), port, sip_register_interval);

			u->add_handler(port, std::bind(&sip::input, sip_, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), nullptr);

			// TODO: ipv6 sip
		}
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		// just fine
	}

	// SNMP
	try {
		const libconfig::Setting & s_snmp = root.lookup("snmp");

		int port = cfg_int(s_snmp, "port", "udp port to listen on", true, 123);

		for(auto & dev : devs) {
			ipv4 *i4 = (ipv4 *)dev->get_protocol(0x0800);
			if (!i4)
				continue;

			udp *const u4 = (udp *)i4->get_ip_protocol(0x11);
			if (!u4)
				continue;

			snmp *snmp_4 = new snmp(&s, u4);
			u4->add_handler(port, std::bind(&snmp::input, snmp_4, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), nullptr);

			ipv6 *i6 = (ipv6 *)dev->get_protocol(0x86dd);
			if (!i6)
				continue;

			udp *const u6 = (udp *)i6->get_ip_protocol(0x11);
			if (!u6)
				continue;

			snmp *snmp_6 = new snmp(&s, u6);
			u6->add_handler(port, std::bind(&snmp::input, snmp_6, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), nullptr);
		}
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		// just fine
	}

	// SYSLOG
	try {
		const libconfig::Setting & s_syslog = root.lookup("syslog");

		int port = cfg_int(s_syslog, "port", "udp port to listen on", true, 123);

		for(auto & dev : devs) {
			ipv4 *i4 = (ipv4 *)dev->get_protocol(0x0800);
			if (!i4)
				continue;

			udp *const u4 = (udp *)i4->get_ip_protocol(0x11);
			if (!u4)
				continue;

			syslog_srv *syslog_4 = new syslog_srv(&s);
			u4->add_handler(port, std::bind(&syslog_srv::input, syslog_4, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), nullptr);

			ipv6 *i6 = (ipv6 *)dev->get_protocol(0x86dd);
			if (!i6)
				continue;

			udp *const u6 = (udp *)i6->get_ip_protocol(0x11);
			if (!u6)
				continue;

			syslog_srv *syslog_6 = new syslog_srv(&s);
			u6->add_handler(port, std::bind(&syslog_srv::input, syslog_6, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), nullptr);
		}
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		// just fine
	}


	dolog(debug, "*** STARTED ***\n");
	printf("*** STARTED ***\n");
	printf("Press enter to terminate\n");

	getchar();

	dolog(info, " *** TERMINATING ***\n");
	fprintf(stderr, "terminating\n");

	for(auto & d : devs)
		d->stop();

	for(auto & p : ip_protocols)
		delete p;

	for(auto & p : protocols)
		delete p;

	for(auto & d : devs)
		delete d;

	dolog(info, "THIS IS THE END\n");

	closelog();

#if 0
	// something that silently drops packet for a port
	tcp_udp_fw *firewall = new tcp_udp_fw(&s, u);
	u->add_handler(22, std::bind(&tcp_udp_fw::input, firewall, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), nullptr);

	std::string run_at_started = iniparser_getstring(ini, "cfg:ifup", "");
	if (run_at_started.empty() == false)
		run(run_at_started);


	std::string run_at_shutdown = iniparser_getstring(ini, "cfg:ifdown", "");
	if (run_at_shutdown.empty() == false)
		run(run_at_shutdown);

	free_handler(http_handler6);
	free_handler(http_handler);

	free_handler(vnc_handler6);
	free_handler(vnc_handler);

	if (vnc_handler6.deinit)
		vnc_handler6.deinit();

	if (vnc_handler.deinit)
		vnc_handler.deinit();

	if (http_handler.deinit)
		http_handler.deinit();
#endif

	return 0;
}
