// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
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
#include "phys_tap.h"
#include "phys_promiscuous.h"
#include "phys_ppp.h"
#include "phys_sctp_udp.h"
#include "phys_slip.h"
#include "arp.h"
#include "dns.h"
#include "ipv4.h"
#include "ipv6.h"
#include "icmp.h"
#include "icmp6.h"
#include "log.h"
#include "arp.h"
#include "mdns.h"
#include "ndp.h"
#include "sip.h"
#include "udp.h"
#include "ntp.h"
#include "syslog.h"
#include "snmp.h"
#include "sctp.h"
#include "tcp.h"
#include "tcp_udp_fw.h"
#include "http.h"
#include "nrpe.h"
#include "vnc.h"
#include "mqtt.h"
#include "str.h"
#include "utils.h"
#include "socks_proxy.h"
#include "echo.h"
#include "lldp.h"


void free_handler(const port_handler_t & tph)
{
       delete tph.pd;
}

log_level_t parse_ll(const std::string & ll)
{
	if (ll == "debug")
		return ll_debug;

	if (ll == "info")
		return ll_info;

	if (ll == "warning")
		return ll_warning;

	if (ll == "error")
		return ll_error;

	fprintf(stderr, "Log-level \"%s\" not understood\n", ll.c_str());

	return ll_debug;
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

	DOLOG(ll_info, "\"%s\" not found (%s), assuming default (%s)\n", key.c_str(), descr, def.c_str());

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

		DOLOG(ll_info, "\"%s\" not found (%s), assuming default (%d)\n", key.c_str(), descr, def);
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

		DOLOG(ll_info, "\"%s\" not found (%s), assuming default (%d)\n", key, descr, def);
	}
	catch(const libconfig::SettingTypeException & ste) {
		error_exit(false, "Expected a boolean value for \"%s\" (%s) but got something else", key, descr);
	}

	return v;
}

void register_tcp_service(std::vector<phys *> *const devs, port_handler_t & tph, const int port)
{
	for(auto & dev : *devs) {
		ipv4 *i4 = dynamic_cast<ipv4 *>(dev->get_protocol(0x0800));
		if (i4) {
			tcp *const t4 = dynamic_cast<tcp *>(i4->get_ip_protocol(0x06));

			if (t4)
				t4->add_handler(port, tph);
		}

		ipv6 *i6 = dynamic_cast<ipv6 *>(dev->get_protocol(0x86dd));
		if (i6) {
			tcp *const t6 = dynamic_cast<tcp *>(i6->get_ip_protocol(0x06));

			if (t6)
				t6->add_handler(port, tph);
		}
	}
}

void register_mdns_service(mdns *const m, std::vector<phys *> *const devs, const int port, const libconfig::Setting & settings)
{
	try {
		std::string hostname = (const char *)settings.lookup("mdns");

		for(auto & dev : *devs) {
			ipv4 *i4 = dynamic_cast<ipv4 *>(dev->get_protocol(0x0800));
			if (i4) {
				udp *const u4 = dynamic_cast<udp *>(i4->get_ip_protocol(0x11));

				if (u4)
					m->add_protocol(u4, port, hostname);
			}

			ipv6 *i6 = dynamic_cast<ipv6 *>(dev->get_protocol(0x86dd));
			if (i6) {
				udp *const u6 = dynamic_cast<udp *>(i6->get_ip_protocol(0x11));

				if (u6)
					m->add_protocol(u6, port, hostname);
			}
		}
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		// just fine
	}
}

void register_sctp_service(std::vector<phys *> *const devs, port_handler_t & sph, const int port)
{
	for(auto & dev : *devs) {
		ipv4 *i4 = dynamic_cast<ipv4 *>(dev->get_protocol(0x0800));
		if (i4) {
			sctp *const s4 = dynamic_cast<sctp *>(i4->get_ip_protocol(0x84));

			if (s4)
				s4->add_handler(port, sph);
		}

		ipv6 *i6 = dynamic_cast<ipv6 *>(dev->get_protocol(0x86dd));
		if (i6) {
			sctp *const s6 = dynamic_cast<sctp *>(i6->get_ip_protocol(0x84));

			if (s6)
				s6->add_handler(port, sph);
		}
	}
}

std::pair<port_handler_t, int> get_http_handler(stats *const s, const libconfig::Setting & s_http)
{
	std::string web_root    = cfg_str(s_http,  "web-root",    "HTTP server files root", false, "");
	std::string web_logfile = cfg_str(s_http,  "web-logfile", "HTTP server logfile", false, "");

	int         port        = cfg_int(s_http,  "port",        "tcp port to listen on", true, 80);

	bool        is_https    = cfg_bool(s_http, "is-https",    "Set to true if https (e.g. port 443)", true, false);

	return { http_get_handler(s, web_root, web_logfile, is_https), port };
}

void progress(const int cur, const int total)
{
	printf("%3.2f%% \r", cur * 100. / total);

	fflush(nullptr);
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

	DOLOG(ll_info, "*** START ***\n");

	signal(SIGINT, ss);

	snmp_data_type_running_since running_since;

	snmp_data sd;
	sd.register_oid("1.3.6.1.2.1.1.1.0", "MyIP - an IP-stack implemented in C++ running in userspace");
	sd.register_oid("1.3.6.1.2.1.1.2.0", new snmp_data_type_oid("1.3.6.1.2.1.4.57850.1"));
	sd.register_oid("1.3.6.1.2.1.1.3.0", &running_since);  // "The time since the network management portion of the system was last re-initialized.
	sd.register_oid("1.3.6.1.2.1.1.4.0", "Folkert van Heusden <mail@vanheusden.com>");
	sd.register_oid("1.3.6.1.2.1.1.5.0", "MyIP");
	sd.register_oid("1.3.6.1.2.1.1.6.0", "The Netherlands, Europe, Earth");
	sd.register_oid("1.3.6.1.2.1.1.7.0", snmp_integer::si_integer, 254 /* everything but the physical layer */);
	sd.register_oid("1.3.6.1.2.1.1.8.0", snmp_integer::si_integer, 0);  // The value of sysUpTime at the time of the most recent change in state or value of any instance of sysORID.

	stats s(16384, &sd);

	/// environment
	int uid = 1000, gid = 1000;
	std::string run_at_started;

	{
		const libconfig::Setting & environment = root.lookup("environment");

		uid = cfg_int(environment, "run-as", "user to run as",  true, 1003);
		gid = cfg_int(environment, "run-in", "group to run in", true, 1003);
		setloguid(uid, gid);

		std::string chdir_path = cfg_str(environment, "chdir-path", "directory to chdir to", true, "/tmp");

		if (chdir(chdir_path.c_str()) == -1) {
			DOLOG(ll_error, "chdir: %s", strerror(errno));
			return 1;
		}

		run_at_started = cfg_str(environment, "ifup", "program to run when network interfaces are up", true, "");
	}

	// used for clean-up
	std::vector<protocol *>    protocols;
	std::vector<ip_protocol *> ip_protocols;
	std::vector<application *> applications;
	std::vector<socks_proxy *> socks_proxies;

	mdns *mdns_ = new mdns();
	applications.push_back(mdns_);

	/// network interfaces
	const libconfig::Setting &interfaces = root["interfaces"];
	size_t n_interfaces = interfaces.getLength();

	sd.register_oid("1.3.6.1.2.1.2.1.0", snmp_integer::si_integer, int(n_interfaces));

	std::vector<phys *> devs;

	for(size_t i=0; i<n_interfaces; i++) {
		const libconfig::Setting &interface = interfaces[i];

		std::string type = cfg_str(interface, "type", "network interface type (e.g. \"ethernet\", \"ppp\" or \"slip\")", true, "ethernet");

		std::string mac = cfg_str(interface, "mac-address", "MAC address", true, "52:34:84:16:44:22");
		any_addr my_mac = parse_address(mac.c_str(), 6, ":", 16);

		printf("%zu] Will listen on MAC address: %s\n", i, my_mac.to_str().c_str());

//		sd.register_oid("1.3.6.1.2.1.2.2.1", snmp_integer::si_integer, int(i + 1));

		sd.register_oid(myformat("1.3.6.1.2.1.2.2.1.1.%zu", i + 1), snmp_integer::si_integer, int(i + 1));

		phys *dev = nullptr;

		if (type == "tap") {
			std::string dev_name = cfg_str(interface, "dev-name", "device name", true, "myip");

			sd.register_oid(myformat("1.3.6.1.2.1.31.1.1.1.1.%zu", i + 1), dev_name);  // name
			sd.register_oid(myformat("1.3.6.1.2.1.2.2.1.2.1.%zu",  i + 1), "MyIP Ethernet device");  // description
			sd.register_oid(myformat("1.3.6.1.2.1.17.1.4.1.%zu",   i + 1), snmp_integer::si_integer, 1);  // device is up (1)

			dev = new phys_tap(i + 1, &s, dev_name, uid, gid);
		}
		else if (type == "promiscuous") {
			std::string dev_name = cfg_str(interface, "dev-name", "device name", false, "eth0");

			dev = new phys_promiscuous(i + 1, &s, dev_name);
		}
		else if (type == "slip" || type == "ppp") {
			std::string dev_name = cfg_str(interface, "serial-dev", "serial port device node", false, "/dev/ttyS0");

			sd.register_oid(myformat("1.3.6.1.2.1.31.1.1.1.1.%zu", i + 1), dev_name);
			sd.register_oid(myformat("1.3.6.1.2.1.2.2.1.2.1.%zu",  i + 1), myformat("MyIP %s device", type.c_str()));

			int baudrate = cfg_int(interface, "baudrate", "serial port baudrate", true, 115200);
			int bps_setting = 0;
			if (baudrate == 9600)
				bps_setting = B9600;
			else if (baudrate == 115200)
				bps_setting = B115200;
			else
				error_exit(false, "\"%d\" cannot be configured", baudrate);

			if (type == "slip")
				dev = new phys_slip(i + 1, &s, dev_name, bps_setting, my_mac);
			else if (type == "ppp") {
				bool emulate_modem_xp = cfg_bool(interface, "emulate-modem-xp", "emulate AT-set modem / XP direct link", true, false);

				std::string oa_str = cfg_str(interface, "opponent-address", "opponent IPv4 address", false, "192.168.3.2");
				any_addr opponent_address = parse_address(oa_str.c_str(), 4, ".", 10);

				dev = new phys_ppp(i + 1, &s, dev_name, bps_setting, my_mac, emulate_modem_xp, opponent_address);
			}
			else {
				error_exit(false, "internal error");
			}
		}
		else if (type == "udp") {
			std::string addr_str = cfg_str(interface, "ip-address", "local IP address", false, "192.168.3.1");
			any_addr local_addr = parse_address(addr_str.c_str(), 4, ".", 10);

			int port = cfg_int(interface, "port", "UDP port number", true, 9899);

			sd.register_oid(myformat("1.3.6.1.2.1.31.1.1.1.1.%zu", i + 1), myformat("udp-%d", port));  // name
			sd.register_oid(myformat("1.3.6.1.2.1.2.2.1.2.1.%zu",  i + 1), "MyIP UDP device");  // description
			sd.register_oid(myformat("1.3.6.1.2.1.17.1.4.1.%zu",   i + 1), snmp_integer::si_integer, 1);  // device is up (1)

			dev = new phys_sctp_udp(i + 1, &s, my_mac, local_addr, port);
		}
		else {
			error_exit(false, "\"%s\" is an unknown network interface type", type.c_str());
		}

		devs.push_back(dev);

		tcp *ipv4_tcp { nullptr };

		any_addr mgmt_addr;

		// ipv4
		try {
			const libconfig::Setting & ipv4_ = interface.lookup("ipv4");

			std::string ma_str = cfg_str(ipv4_, "my-address", "IPv4 address", false, "192.168.3.2");
			any_addr my_address = parse_address(ma_str.c_str(), 4, ".", 10);

			mgmt_addr = my_address;

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
				tcp *t = new tcp(&s, icmp_);
				ipv4_instance->register_protocol(0x06, t);

				ipv4_tcp = t;

				ip_protocols.push_back(t);
			}

			bool use_sctp = cfg_bool(ipv4_, "use-sctp", "wether to enable sctp", true, true);
			if (use_sctp) {
				DOLOG(ll_debug, "Adding SCTP to IPv4\n");

				sctp *stcp_ = new sctp(&s, icmp_);
				ipv4_instance->register_protocol(0x84, stcp_);

				ip_protocols.push_back(stcp_);
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

			if (mgmt_addr.is_set() == false)
				mgmt_addr = my_ip6;

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
				tcp *t6 = new tcp(&s, icmp6_);
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

		// LLDP
		lldp *lldp_ = new lldp(&s, my_mac, mgmt_addr, i + 1);
		protocols.push_back(lldp_);
		dev->register_protocol(0x0806, lldp_);

		// socks proxy
		try {
			const libconfig::Setting & socks = interface.lookup("socks");

			if (!ipv4_tcp)
				error_exit(false, "socks requires a TCP layer");

			std::string interface = cfg_str(socks, "interface", "address of interface to listen on", true, "0.0.0.0");
			int port = cfg_int(socks, "port", "port to listen on", true, 1080);

			printf("Starting socks listener on %s:%d\n", interface.c_str(), port);

			socks_proxy *so = new socks_proxy(interface, port, ipv4_tcp);
			socks_proxies.push_back(so);

			// DNS
			try {
				const libconfig::Setting & s_dns = socks.lookup("dns");

				std::string dns_u_ip_str = cfg_str(s_dns, "host", "upstream DNS server", false, "");
				any_addr upstream_dns_server = parse_address(dns_u_ip_str.c_str(), 4, ".", 10);

				dns *dns_ = nullptr;

				for(auto & dev : devs) {
					ipv4 *i4 = dynamic_cast<ipv4 *>(dev->get_protocol(0x0800));
					if (!i4)
						continue;

					udp *const u = dynamic_cast<udp *>(i4->get_ip_protocol(0x11));
					if (!u)
						continue;

					dns_ = new dns(&s, u, i4->get_addr(), upstream_dns_server);

					u->add_handler(53, std::bind(&dns::input, dns_, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), nullptr);

					applications.push_back(dns_);
				}

				if (dns_)
					so->register_dns(dns_);
			}
			catch(const libconfig::SettingNotFoundException &nfex) {
				// just fine
			}
		}
		catch(const libconfig::SettingNotFoundException &nfex) {
			// just fine
		}

		dev->start();
	}

	if (run_at_started.empty() == false)
		run(run_at_started);

#if 0
	if (setgid(gid) == -1) {
		DOLOG(ll_error, "setgid: %s", strerror(errno));
		return 1;
	}

	if (setuid(uid) == -1) {
		DOLOG(ll_error, "setuid: %s", strerror(errno));
		return 1;
	}
#endif

	// NTP
	try {
		const libconfig::Setting & s_ntp = root.lookup("ntp");

		std::string ntp_u_ip_str = cfg_str(s_ntp, "upstream-ip-address", "upstream NTP server", false, "");
		any_addr upstream_ntp_server = parse_address(ntp_u_ip_str.c_str(), 4, ".", 10);

		int port = cfg_int(s_ntp, "port", "udp port to listen on", true, 123);

		for(auto & dev : devs) {
			ipv4 *i4 = dynamic_cast<ipv4 *>(dev->get_protocol(0x0800));
			if (!i4)
				continue;

			udp *const u = dynamic_cast<udp *>(i4->get_ip_protocol(0x11));
			if (!u)
				continue;

			ntp *ntp_ = new ntp(&s, u, i4->get_addr(), upstream_ntp_server, true);

			u->add_handler(port, std::bind(&ntp::input, ntp_, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), nullptr);

			applications.push_back(ntp_);
		}
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		// just fine
	}

	// HTTP
	try {
		const libconfig::Setting & s_http = root.lookup("http");

		auto rc = get_http_handler(&s, s_http);

		register_tcp_service(&devs, rc.first, rc.second);

		register_sctp_service(&devs, rc.first, rc.second);

		register_mdns_service(mdns_, &devs, rc.second, s_http);
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		// just fine
	}

	// HTTPS
	try {
		const libconfig::Setting & s_http = root.lookup("https");

		std::string web_root    = cfg_str(s_http,  "web-root",    "HTTP server files root", false, "");
		std::string web_logfile = cfg_str(s_http,  "web-logfile", "HTTP server logfile", false, "");

		auto rc = get_http_handler(&s, s_http);

		http_private_data *hpd = dynamic_cast<http_private_data *>(rc.first.pd);

		std::string temppk = cfg_str(s_http, "private-key", "Private key .key-file", false, "");

	        auto pk_str = load_text_file(temppk);
		if (pk_str.has_value() == false)
			error_exit(false, "Failed to load private key file");

		hpd->private_key = pk_str.value();

		std::string tempc = cfg_str(s_http, "certificate", "Certificate .crt-file", false, "");

	        auto c_str = load_text_file(tempc);
		if (c_str.has_value() == false)
			error_exit(false, "Failed to load certificate file");

		hpd->certificate = c_str.value();

		register_tcp_service(&devs, rc.first, rc.second);

		register_sctp_service(&devs, rc.first, rc.second);

		register_mdns_service(mdns_, &devs, rc.second, s_http);
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		// just fine
	}

	// NRPE
	try {
		const libconfig::Setting & s_nrpe = root.lookup("nrpe");

		int port = cfg_int(s_nrpe, "port", "tcp port to listen on", true, 5666);

		port_handler_t nrpe_handler = nrpe_get_handler(&s);

		register_tcp_service(&devs, nrpe_handler, port);

		register_sctp_service(&devs, nrpe_handler, port);

		register_mdns_service(mdns_, &devs, port, s_nrpe);
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		// just fine
	}

	// VNC
	try {
		const libconfig::Setting & s_vnc = root.lookup("vnc");

		int port = cfg_int(s_vnc, "port", "tcp port to listen on", true, 5900);

		port_handler_t vnc_handler = vnc_get_handler(&s);

		register_tcp_service(&devs, vnc_handler, port);

		register_sctp_service(&devs, vnc_handler, port);

		register_mdns_service(mdns_, &devs, port, s_vnc);
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		// just fine
	}

	// MQTT
	try {
		const libconfig::Setting & s_mqtt = root.lookup("mqtt");

		int port = cfg_int(s_mqtt, "port", "tcp port to listen on", true, 1883);

		port_handler_t mqtt_handler = mqtt_get_handler(&s);

		register_tcp_service(&devs, mqtt_handler, port);

		register_sctp_service(&devs, mqtt_handler, port);

		register_mdns_service(mdns_, &devs, port, s_mqtt);
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
			ipv4 *i4 = dynamic_cast<ipv4 *>(dev->get_protocol(0x0800));
			if (i4) {
				udp *const u4 = dynamic_cast<udp *>(i4->get_ip_protocol(0x11));

				if (u4) {
					sip *sip_ = new sip(&s, u4, sample, mb_path, mb_recv_script, upstream_sip_server, upstream_sip_user, upstream_sip_password, i4->get_addr(), port, sip_register_interval);

					u4->add_handler(port, std::bind(&sip::input, sip_, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), nullptr);

					applications.push_back(sip_);
				}
			}

			// TODO: ipv6 SIP

			// TODO: ipv4/6 SIP over SCTP
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
			ipv4 *i4 = dynamic_cast<ipv4 *>(dev->get_protocol(0x0800));
			if (!i4)
				continue;

			udp *const u4 = dynamic_cast<udp *>(i4->get_ip_protocol(0x11));
			if (!u4)
				continue;

			snmp *snmp_4 = new snmp(&sd, &s, u4);
			u4->add_handler(port, std::bind(&snmp::input, snmp_4, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), nullptr);

			ipv6 *i6 = dynamic_cast<ipv6 *>(dev->get_protocol(0x86dd));
			if (!i6)
				continue;

			udp *const u6 = dynamic_cast<udp *>(i6->get_ip_protocol(0x11));
			if (!u6)
				continue;

			snmp *snmp_6 = new snmp(&sd, &s, u6);
			u6->add_handler(port, std::bind(&snmp::input, snmp_6, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), nullptr);

			applications.push_back(snmp_4);
			applications.push_back(snmp_6);
		}
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		// just fine
	}

	// echo
	port_handler_t echo_sph = echo_get_handler();

	register_tcp_service(&devs, echo_sph, 7);  // port 7 (TCP) is 'echo'

	register_sctp_service(&devs, echo_sph, 7);  // port 7 (TCP) is 'echo'

	// SYSLOG
	try {
		const libconfig::Setting & s_syslog = root.lookup("syslog");

		int port = cfg_int(s_syslog, "port", "udp port to listen on", true, 123);

		for(auto & dev : devs) {
			ipv4 *i4 = dynamic_cast<ipv4 *>(dev->get_protocol(0x0800));
			if (!i4)
				continue;

			udp *const u4 = dynamic_cast<udp *>(i4->get_ip_protocol(0x11));
			if (!u4)
				continue;

			syslog_srv *syslog_4 = new syslog_srv(&s);
			u4->add_handler(port, std::bind(&syslog_srv::input, syslog_4, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), nullptr);

			ipv6 *i6 = dynamic_cast<ipv6 *>(dev->get_protocol(0x86dd));
			if (!i6)
				continue;

			udp *const u6 = dynamic_cast<udp *>(i6->get_ip_protocol(0x11));
			if (!u6)
				continue;

			syslog_srv *syslog_6 = new syslog_srv(&s);
			u6->add_handler(port, std::bind(&syslog_srv::input, syslog_6, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), nullptr);

			applications.push_back(syslog_4);
			applications.push_back(syslog_6);
		}
	}
	catch(const libconfig::SettingNotFoundException &nfex) {
		// just fine
	}

	DOLOG(ll_debug, "*** STARTED ***\n");
	printf("*** STARTED ***\n");
	printf("Press enter to terminate\n");

	getchar();

	DOLOG(ll_info, " *** TERMINATING ***\n");
	fprintf(stderr, "terminating fase 1\n");

	int n_actions = 0;

	for(auto & s : socks_proxies)
		s-> ask_to_stop(), n_actions++;

	for(auto & a : applications)
		a->ask_to_stop(), n_actions++;

	for(auto & d : devs)
		d->ask_to_stop(), n_actions++;

	for(auto & p : ip_protocols)
		p->ask_to_stop(), n_actions++;

	for(auto & p : protocols)
		p->ask_to_stop(), n_actions++;

	fprintf(stderr, "Number of actions left: %d\n", n_actions);

	fprintf(stderr, "terminating fase 2\n");
	int n_actions_done = 0;

	for(auto & s : socks_proxies) {
		progress(n_actions_done++, n_actions);
		delete s;
	}

	for(auto & a : applications) {
		progress(n_actions_done++, n_actions);
		delete a;
	}

	for(auto & p : ip_protocols) {
		progress(n_actions_done++, n_actions);
		delete p;
	}

	for(auto & p : protocols) {
		progress(n_actions_done++, n_actions);
		delete p;
	}

	for(auto & d : devs) {
		progress(n_actions_done++, n_actions);
		delete d;
	}

	DOLOG(ll_info, "THIS IS THE END\n");

	closelog();

#if 0
	// something that silently drops packet for a port
	tcp_udp_fw *firewall = new tcp_udp_fw(&s, u);
	u->add_handler(22, std::bind(&tcp_udp_fw::input, firewall, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), nullptr);


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
