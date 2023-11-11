// (C) 2022-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <algorithm>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pty.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "log.h"
#include "phys_kiss.h"
#include "packet.h"
#include "str.h"
#include "utils.h"


#define MAX_PACKET_SIZE 256

#define FEND	0xc0
#define FESC	0xdb
#define TFEND	0xdc
#define TFESC	0xdd

void escape_put(uint8_t **p, int *len, uint8_t c)
{
	if (c == FEND) {
		(*p)[(*len)++] = FESC;
		(*p)[(*len)++] = TFEND;
	}
	else if (c == FESC) {
		(*p)[(*len)++] = FESC;
		(*p)[(*len)++] = TFESC;
	}
	else {
		(*p)[(*len)++] = c;
	}
}

void set_nodelay(int fd)
{
        int on = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof(int)) == -1)
                error_exit(true, "set_nodelay: TCP_NODELAY failed");
}

int connect_to(const char *host, const int portnr)
{
        struct addrinfo hints = { 0 };
        hints.ai_family = AF_UNSPEC;    // Allow IPv4 or IPv6
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;    // For wildcard IP address
        hints.ai_protocol = 0;          // Any protocol
        hints.ai_canonname = nullptr;
        hints.ai_addr = nullptr;
        hints.ai_next = nullptr;

        char portnr_str[8] = { 0 };
        snprintf(portnr_str, sizeof portnr_str, "%d", portnr);

        struct addrinfo *result = nullptr;
        int rc = getaddrinfo(host, portnr_str, &hints, &result);
        if (rc != 0)
                error_exit(false, "connect_to: problem resolving %s: %s", host, gai_strerror(rc));

        for(struct addrinfo *rp = result; rp != nullptr; rp = rp->ai_next) {
                int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (fd == -1)
                        continue;

                if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
                        freeaddrinfo(result);

			set_nodelay(fd);

                        return fd;
                }

                close(fd);
        }

        freeaddrinfo(result);

        return -1;
}

int accept_socket(const std::string & listen_addr, const int listen_port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		error_exit(true, "accept_socket: failed to create socket: %s", strerror(errno));

	int reuse_addr = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse_addr, sizeof(reuse_addr)) == -1)
		error_exit(true, "accept_socket: failed to set \"re-use address\": %s", strerror(errno));

	struct sockaddr_in servaddr { 0 };
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(listen_port);

	if (inet_aton(listen_addr.c_str(), &servaddr.sin_addr) == -1)
		error_exit(true, "accept_socket: problem interpreting \"%s\": %s", listen_addr.c_str(), strerror(errno));

	if (bind(fd, reinterpret_cast<sockaddr *>(&servaddr), sizeof(servaddr)) == -1)
		error_exit(true, "accept_socket: failed to bind to [%s]:%d: %s", listen_addr.c_str(), listen_port, strerror(errno));

	if (listen(fd, SOMAXCONN) == -1)
		error_exit(true, "accept_socket: failed to listen on socket: %s", strerror(errno));

	int qlen = SOMAXCONN;
	if (setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen)) == -1)
		error_exit(true, "accept_socket: failed to enable \"tcp fastopen\": %s", strerror(errno));

	CDOLOG(ll_info, "[kiss]", "listening on [%s]:%d\n", listen_addr.c_str(), listen_port);

	for(;;) {
		int cfd = accept(fd, nullptr, nullptr);

		if (cfd != -1)
			return cfd;

		CDOLOG(ll_info, "[kiss]", "accept failed: %s\n", strerror(errno));
	}

	return -1;
}

phys_kiss::phys_kiss(const size_t dev_index, stats *const s, const std::string & descr, const any_addr & my_callsign, std::optional<std::pair<std::string, int> > beacon, router *const r) :
	phys(dev_index, s, "kiss-" + descr, r),
	descriptor(descr),
	my_callsign(my_callsign),
	beacon(beacon)
{
	auto parts = split(descriptor, ":");

	if (parts.at(0) == "tcp-server") {
		th_kiss_tcp = new std::thread(&phys_kiss::tcp_kiss_server, this);
	}
	else if (parts.at(0) == "pty-master") {
		int  master = 0;
		int  slave  = 0;
		char name[256] { 0 };

		if (openpty(&master, &slave, name, nullptr, nullptr) == -1)
			error_exit(true, "openpty failed");

		fd = master;

		CDOLOG(ll_info, "[kiss]", "created pty %s which will be linked to \"%s\"\n", name, parts.at(1).c_str());

		if (unlink(parts.at(1).c_str()) == -1 && errno != ENOENT)
			error_exit(true, "Failed to remove \"%s\" from filesystem", parts.at(1).c_str());

		if (symlink(name, parts.at(1).c_str()) == -1)
			error_exit(true, "Failed to create symlink from %s to \"%s\"", name, parts.at(1).c_str());
	}
	else if (parts.at(0) == "tty" || parts.at(0) == "pty-client") {
		fd = open(parts.at(1).c_str(), O_RDWR | O_NOCTTY);
		if (fd == -1)
			error_exit(true, "Failed to open tty (%s)", parts.at(1).c_str());

		if (parts.at(0) == "tty") {
			termios tty     { 0 };
			termios tty_old { 0 };

			if (tcgetattr(fd, &tty) == -1)
				error_exit(true, "phys_kiss: tcgetattr failed");

			tty_old = tty;

			int     tty_bps = atoi(parts.at(2).c_str());
			speed_t speed   = B9600;

			if (tty_bps == 9600) {
				// default
			}
			else if (tty_bps == 19200) {
				speed = B19200;
			}
			else if (tty_bps == 115200) {
				speed = B115200;
			}

			cfsetospeed(&tty, speed);

			tty.c_cflag &= ~PARENB;           // 8N1
			tty.c_cflag &= ~CSTOPB;
			tty.c_cflag &= ~CSIZE;
			tty.c_cflag |=  CS8;

			tty.c_cflag &= ~CRTSCTS;         // no flow control
			tty.c_cflag |=  CREAD | CLOCAL;  // ignore control lines

			cfmakeraw(&tty);

			tcflush(fd, TCIFLUSH);

			if (tcsetattr(fd, TCSANOW, &tty) != 0)
				error_exit(true, "phys_kiss: tcsetattr failed");
		}
	}
	else if (parts.at(0) == "file") {
		fd = open(parts.at(1).c_str(), O_RDONLY);
		if (fd == -1)
			error_exit(true, "Failed to open file (%s)", parts.at(1).c_str());
	}

	(void)reconnect();

	if (parts.at(0) != "tcp-server")
		th = new std::thread(std::ref(*this));

	if (beacon.has_value())
		th_beacon = new std::thread(&phys_kiss::send_beacon, this);
}

void phys_kiss::tcp_kiss_server()
{
	auto parts = split(descriptor, ":");

	while(!stop_flag) {
		int cfd = accept_socket(parts.at(1).c_str(), atoi(parts.at(2).c_str()));

		std::thread th(&phys_kiss::handle_kiss, this, cfd);
		th.detach();

		CDOLOG(ll_error, "[kiss]", "TCP socket connected (server)\n");
	}
}

bool phys_kiss::reconnect()
{
	auto parts = split(descriptor, ":");

	if (parts.at(0) == "tcp-client") {
		for(;;) {
			if (fd != -1) {
				close(fd);
				fd = -1;
			}

			fd = connect_to(parts.at(1).c_str(), atoi(parts.at(2).c_str()));

			if (fd != -1) {
				CDOLOG(ll_error, "[kiss]", "TCP socket connected (client)\n");

				return true;
			}

			CDOLOG(ll_error, "[kiss]", "TCP socket connected (client) failed\n");

			sleep(1);
		}
	}

	return false;
}

phys_kiss::~phys_kiss()
{
	close(fd);

	if (th_beacon) {
		th_beacon->join();
		delete th_beacon;
	}
}

bool phys_kiss::transmit_ax25(const ax25_packet & a)
{
	auto     packet  = a.generate_packet();

	int      max_len = packet.second * 2 + 3;
	uint8_t *out     = reinterpret_cast<uint8_t *>(malloc(max_len));
	int      offset  = 0;

	constexpr uint8_t  cmd     = 0;
	constexpr uint8_t  channel = 0;

	assert(cmd < 16);
	assert(channel < 16);

	out[offset++] = FEND;

	escape_put(&out, &offset, (channel << 4) | cmd);

	for(size_t i=0; i<packet.second; i++)
		escape_put(&out, &offset, packet.first[i]);

	out[offset++] = FEND;

	send_lock.lock();

	ssize_t rc = WRITE(fd, out, offset);

	send_lock.unlock();

	free(out);

	if (rc != offset) {
		CDOLOG(ll_error, "[kiss]", "failed writing to kiss device (%zd of %d sent)\n", rc, offset);

		(void)reconnect();

		return false;
	}

	return true;
}

void phys_kiss::send_beacon()
{
	sleep(2);

	while(!stop_flag) {
		ax25_packet a;
		a.set_from   (my_callsign);
		a.set_to     ("IDENT", '0', true, false);
		a.set_control(0x03);  // unnumbered information/frame
		a.set_data   (reinterpret_cast<const uint8_t *>(beacon.value().first.c_str()), beacon.value().first.size());
		a.set_pid(0xf0);  // beacon

		CDOLOG(ll_debug, "[kiss]", "transmit beacon: \"%s\" (%s)\n", beacon.value().first.c_str(), a.to_str().c_str());
		transmit_ax25(a);

		sleep(beacon.value().second);
	}
}

bool phys_kiss::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload_in, const size_t pl_size_in)
{
	CDOLOG(ll_debug, "[kiss]", "transmit_packet: %s => %s, ethertype: %04x, %zu bytes\n", src_mac.to_str().c_str(), dst_mac.to_str().c_str(), ether_type, pl_size_in);

	assert(src_mac.get_family() == any_addr::ax25);
	assert(dst_mac.get_family() == any_addr::ax25);

	ax25_packet *a = new ax25_packet();
	a->set_from   (src_mac);
	a->set_to     (dst_mac);
	a->set_control(0x03);  // unnumbered information/frame
	a->set_data   (payload_in, pl_size_in);

	if (ether_type == 0x0800 || ether_type == 0x86dd)
		a->set_pid(0xcc);  // ARPA Internet Protocol (IPv4/IPv6)
	else if (ether_type == 0x0806)
		a->set_pid(0xcd);  // ARPA Adress Resolving Protocol (IPv4)
	else if (ether_type == 0x08ff) {
		delete a;

		// it looks like BPQ frames (AX.25 over Ethernet) are regular Ethernet frames with
		// ether-type 0x08ff, then for the payload a 0x00 and then the whole AX.25 packet
		// (without HDLC framing)
		a = new ax25_packet(std::vector<uint8_t>(payload_in + 1, payload_in + pl_size_in - 1));
	}
	else {
		CDOLOG(ll_info, "[kiss]", "transmit_packet: cannot transmit ethertype %04x over AX.25\n", ether_type);
		return false;
	}

	bool rc = transmit_ax25(*a);
	delete a;
	return rc;
}

bool process_kiss_packet(const timespec & ts, const std::vector<uint8_t> & in, std::map<uint16_t, network_layer *> *const prot_map, router *const r, phys *const source_phys)
{
	bool        rc = true;
	ax25_packet ap(in);

	if (ap.get_valid()) {
		std::string payload_str = bin_to_text(in.data(), in.size(), true);

		bool route_as_is = false;

		if (source_phys)
			r->add_ax25_route(ap.get_from().get_any_addr(), { source_phys }, { });

		if (ap.get_type() == ax25_packet::frame_type::TYPE_I) {
			if (ap.get_pid().has_value() == false) {
				CDOLOG(ll_info, "[kiss]", "PID missing in I-frame\n");

				return false;
			}

			int pid = ap.get_pid().value();

			std::string log_prefix = myformat("KISS[%s]", ap.get_from().get_any_addr().to_str().c_str());
			CDOLOG(ll_info, "[kiss]", "%s: received packet of %zu bytes\n", ap.to_str().c_str(), in.size());

			if (pid == 0xcc) {  // check for valid IPv4 payload
				auto payload = ap.get_data();
				int  pl_size = payload.get_n_bytes_left();

				packet *p = new packet(ts, ap.get_from().get_any_addr(), ap.get_from().get_any_addr(), ap.get_to().get_any_addr(), payload.get_bytes(pl_size), pl_size, nullptr, 0, log_prefix);

				int ip_version = p->get_data()[0] >> 4;

				std::optional<uint16_t> ether_type;

				if (ip_version == 4)
					ether_type = 0x0800;
				else if (ip_version == 6)
					ether_type = 0x86dd;
				else
					CDOLOG(ll_info, "[kiss]", "pid %02x (%zu bytes): IP version %d not supported\n", pid, in.size(), ip_version);

				if (ether_type.has_value()) {
					auto it = prot_map->find(ether_type.value());
					if (it != prot_map->end())
						it->second->queue_incoming_packet(source_phys, p);
					else
						CDOLOG(ll_info, "[kiss]", "pid %02x (%zu bytes): ether_type %04x not supported\n", pid, in.size(), ether_type.value());
				}
			}
			else if (pid == 0xf0) {  // usually beacons etc
				std::string payload_str = bin_to_text(in.data(), in.size(), true);

				CDOLOG(ll_info, "[kiss]", "pid %02x (%zu bytes): %s\n", pid, in.size(), payload_str.c_str());
			}
			else if (pid == 0xcd) {  // check for valid ARP payload
				auto payload = ap.get_data();
				int  pl_size = payload.get_n_bytes_left();

				packet *p = new packet(ts, ap.get_from().get_any_addr(), ap.get_from().get_any_addr(), ap.get_to().get_any_addr(), payload.get_bytes(pl_size), pl_size, nullptr, 0, log_prefix);

				auto it = prot_map->find(0x0806);
				if (it != prot_map->end())
					it->second->queue_incoming_packet(source_phys, p);
				else {
					CDOLOG(ll_info, "[kiss]", "No ARP instance available");

					rc = false;
				}
			}
			else {
				CDOLOG(ll_info, "[kiss]", "don't know how to handle pid %02x (%zu bytes): %s, routing it\n", pid, in.size(), payload_str.c_str());

				route_as_is = true;
			}
		}
		else {
			route_as_is = true;
		}

		if (route_as_is) {
			size_t   bpq_size = in.size() + 1;
			uint8_t *work = new uint8_t[bpq_size]();
			memcpy(&work[1], in.data(), in.size());

			if (r->route_packet(ap.get_to().get_any_addr(), 0x08ff, { }, ap.get_from().get_any_addr(), { }, work, bpq_size) == false) {
				CDOLOG(ll_warning, "[kiss]", "failed routing! %d bytes: %s\n", in.size(), payload_str.c_str());

				rc = false;
			}

			delete [] work;
		}
	}
	else {
		// TODO: Ethernet-over-AX.25
		CDOLOG(ll_warning, "[kiss]", "Not a valid AX.25 packet; not processing\n");
	}

	return rc;
}

void phys_kiss::operator()()
{
	CDOLOG(ll_debug, "[kiss]", "thread started\n");

	set_thread_name("myip-phys_kiss");

	handle_kiss(fd);

	CDOLOG(ll_info, "[kiss]", "thread stopped\n");
}

void phys_kiss::handle_kiss(const int cfd)
{
	timespec ts { 0, 0 };

	struct stat fd_stat { 0 };
	if (fstat(cfd, &fd_stat) == -1) {
		CDOLOG(ll_error, "[kiss]", "fstat failed: %s\n", strerror(errno));
		return;
	}

	bool is_a_file = (fd_stat.st_mode & S_IFMT) == S_IFREG;

	if (is_a_file)
		CDOLOG(ll_info, "[kiss]", "Input is a file\n");

	pollfd fds[] = { { cfd, POLLIN, 0 } };

	while(!stop_flag) {
		// TODO: move into next for-loop
		if (!is_a_file) {
			int rc = poll(fds, 1, 150);
			if (rc == -1) {
				if (errno == EINTR)
					continue;

				CDOLOG(ll_error, "[kiss]", "poll: %s\n", strerror(errno));

				if (reconnect() == false)
					break;
				continue;
			}

			if (rc == 0)
				continue;
		}

		bool     ok     = false;
		bool     escape = false;

		uint8_t *p      = reinterpret_cast<uint8_t *>(malloc(MAX_PACKET_SIZE));
		size_t   len    = 0;

		for(;!stop_flag;)
		{
			uint8_t buffer = 0;

			int rc = read(cfd, &buffer, 1);
			if (rc == -1) {
				if (errno == EINTR)
					continue;

				CDOLOG(ll_error, "[kiss]", "failed reading from device\n");
				len = 0;
				(void)reconnect();
				break;
			}

			if (rc == 0) {
				if (is_a_file)
					return;
				break;
			}

			if (escape) {
				if (len == MAX_PACKET_SIZE)
					break;

				if (buffer == TFEND)
					p[len++] = FEND;
				else if (buffer == TFESC)
					p[len++] = FESC;
				else
					CDOLOG(ll_error, "[kiss]", "unexpected escape %02x\n", buffer);

				escape = false;
			}
			else if (buffer == FEND) {
				if (len) {
					ok = true;
					break;
				}

				// otherwise: first FEND, ignore

				if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
					CDOLOG(ll_warning, "[kiss]", "clock_gettime failed: %s\n", strerror(errno));
			}
			else if (buffer == FESC)
				escape = true;
			else
			{
				if (len == MAX_PACKET_SIZE)
					break;

				p[len++] = buffer;
			}
		}

		if (len == 0)
			ok = false;

		if (ok)
		{
			int cmd = p[0] & 0x0f;

			CDOLOG(ll_debug, "[kiss]", "port: %d, cmd: %d, len: %d\n", (p[0] >> 4) & 0x0f, cmd, len);

			if (cmd == 1)
				CDOLOG(ll_debug, "[kiss]", "TX delay: %d\n", p[1] * 10);
			else if (cmd == 2)
				CDOLOG(ll_debug, "[kiss]", "persistance: %d\n", p[1] * 256 - 1);
			else if (cmd == 3)
				CDOLOG(ll_debug, "[kiss]", "slot time: %dms\n", p[1] * 10);
			else if (cmd == 4)
				CDOLOG(ll_debug, "[kiss]", "txtail: %dms\n", p[1] * 10);
			else if (cmd == 5)
				CDOLOG(ll_debug, "[kiss]", "full duplex: %d\n", p[1]);
			else if (cmd == 6)
				CDOLOG(ll_debug, "[kiss]", "set hardware\n");
			else if (cmd == 15)
				CDOLOG(ll_info, "[kiss]", "kernel asked for shutdown\n");

			len--;

			if (len)
				memmove(&p[0], &p[1], len);
		}

		if (ok) {
			CDOLOG(ll_debug, "[kiss]", "packet received\n");

			std::vector<uint8_t> payload_v(p, p + len);

			ok = process_kiss_packet(ts, payload_v, &prot_map, r, this);
		}

		free(p);
	}
}
