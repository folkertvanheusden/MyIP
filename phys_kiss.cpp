// (C) 2022-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <algorithm>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ax25.h"
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

phys_kiss::phys_kiss(const size_t dev_index, stats *const s, const std::string & dev_file, const int tty_bps, const any_addr & my_callsign, std::optional<std::pair<std::string, int> > beacon, const bool is_server, router *const r, const bool init_tty) :
	phys(dev_index, s, "kiss-" + dev_file),
	my_callsign(my_callsign),
	beacon(beacon),
	r(r)
{
	if (is_server) {
		int  master = 0;
		int  slave  = 0;
		char name[256] { 0 };

		if (openpty(&master, &slave, name, nullptr, nullptr) == -1)
			error_exit(true, "openpty failed");

		fd = master;

		CDOLOG(ll_info, "[kiss]", "created pty %s which will be linked to \"%s\"\n", name, dev_file.c_str());

		if (unlink(dev_file.c_str()) == -1 && errno != ENOENT)
			error_exit(true, "Failed to remove \"%s\" from filesystem", dev_file.c_str());

		if (symlink(name, dev_file.c_str()) == -1)
			error_exit(true, "Failed to create symlink from %s to \"%s\"", name, dev_file.c_str());
	}
	else {
		fd = open(dev_file.c_str(), O_RDWR | O_NOCTTY);

		if (fd == -1)
			error_exit(true, "Failed to open tty (%s)", dev_file.c_str());

		if (init_tty) {
			termios tty     { 0 };
			termios tty_old { 0 };

			if (tcgetattr(fd, &tty) == -1)
				error_exit(true, "tcgetattr failed");

			tty_old = tty;

			speed_t speed = B9600;

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
				error_exit(true, "tcsetattr failed");
		}
	}

	th = new std::thread(std::ref(*this));

	if (beacon.has_value())
		th_beacon = new std::thread(&phys_kiss::send_beacon, this);
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
		CDOLOG(ll_error, "[kiss]", "failed writing to kiss device");

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

	ax25_packet a;
	a.set_from   (src_mac);
	a.set_to     (dst_mac);
	a.set_control(0x03);  // unnumbered information/frame
	a.set_data   (payload_in, pl_size_in);

	if (ether_type == 0x0800 || ether_type == 0x86dd)
		a.set_pid(0xcc);  // ARPA Internet Protocol (IPv4/IPv6)
	else if (ether_type == 0x0806)
		a.set_pid(0xcd);  // ARPA Adress Resolving Protocol (IPv4)
	else {
		CDOLOG(ll_info, "[kiss]", "transmit_packet: cannot transmit ethertype %04x over AX.25\n", ether_type);
		return false;
	}

	return transmit_ax25(a);
}

void phys_kiss::operator()()
{
	CDOLOG(ll_debug, "[kiss]", "thread started\n");

	set_thread_name("myip-phys_kiss");

	struct timespec ts { 0, 0 };

	struct pollfd fds[] = { { fd, POLLIN, 0 } };

	while(!stop_flag) {
		int rc = poll(fds, 1, 150);
		if (rc == -1) {
			if (errno == EINTR)
				continue;

			CDOLOG(ll_error, "[kiss]", "poll: %s", strerror(errno));
			exit(1);
		}

		if (rc == 0)
			continue;

		bool     ok     = false;
		bool     escape = false;

		uint8_t *p      = reinterpret_cast<uint8_t *>(malloc(MAX_PACKET_SIZE));
		size_t   len    = 0;

		for(;!stop_flag;)
		{
			uint8_t buffer = 0;

			if (read(fd, &buffer, 1) == -1) {
				if (errno == EINTR)
					continue;

				CDOLOG(ll_error, "[kiss]", "failed reading from device");

				break;
			}

			if (escape)
			{
				if (len == MAX_PACKET_SIZE)
					break;

				if (buffer == TFEND)
					p[len++] = FEND;
				else if (buffer == TFESC)
					p[len++] = FESC;
				else
					CDOLOG(ll_error, "[kiss]", "unexpected escape %02x", buffer);

				escape = false;
			}
			else if (buffer == FEND)
			{
				if (len) {
					ok = true;
					break;
				}

				// otherwise: first FEND, ignore

				if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
					CDOLOG(ll_warning, "[kiss]", "clock_gettime failed: %s", strerror(errno));
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
			std::vector<uint8_t> payload_v(p, p + len);
			ax25_packet          ap(payload_v);

			r->add_ax25_route(ap.get_from().get_any_addr(), { this }, { });

			int pid = ap.get_pid().has_value() ? ap.get_pid().value() : -1;

			std::string log_prefix;

			if (ap.get_valid()) {
				log_prefix = myformat("KISS[%s]", ap.get_from().get_any_addr().to_str().c_str());

				CDOLOG(ll_info, "[kiss]", "%s: received packet of %d bytes\n",
						ap.to_str().c_str(), len);
			}

			if (ap.get_valid() && pid == 0xcc) {  // check for valid IPv4 payload
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
					CDOLOG(ll_info, "[kiss]", "pid %02x (%d bytes): IP version %d not supported\n", pid, len, ip_version);

				if (ether_type.has_value()) {
					auto it = prot_map.find(ether_type.value());
					if (it != prot_map.end())
						it->second->queue_incoming_packet(this, p);
					else
						CDOLOG(ll_info, "[kiss]", "pid %02x (%d bytes): ether_type %04x not supported\n", pid, len, ether_type.value());
				}
			}
			else if (pid == 0xf0) {  // usually beacons etc
				std::string payload_str = bin_to_text(p, len, true);

				CDOLOG(ll_info, "[kiss]", "pid %02x (%d bytes): %s\n", pid, len, payload_str.c_str());
			}
			else if (ap.get_valid() && pid == 0xcd) {  // check for valid ARP payload
				auto payload = ap.get_data();
				int  pl_size = payload.get_n_bytes_left();

				packet *p = new packet(ts, ap.get_from().get_any_addr(), ap.get_from().get_any_addr(), ap.get_to().get_any_addr(), payload.get_bytes(pl_size), pl_size, nullptr, 0, log_prefix);

				auto it = prot_map.find(0x0806);
				if (it != prot_map.end())
					it->second->queue_incoming_packet(this, p);
			}
			else {
				auto payload = ap.get_data();
				int  pl_size = payload.get_n_bytes_left();

				std::string payload_str = bin_to_text(p, len, true);

				CDOLOG(ll_info, "[kiss]", "don't know how to handle pid %02x (%d bytes): %s\n", pid, len, payload_str.c_str());

				if (r->route_packet(ap.get_to().get_any_addr(), 0x08FF, { }, ap.get_from().get_any_addr(), { }, payload.get_bytes(pl_size), pl_size) == false) {
					CDOLOG(ll_warning, "[kiss]", "failed routing! pid %02x (%d bytes): %s\n", pid, len, payload_str.c_str());
				}
			}
		}

		free(p);
	}

	CDOLOG(ll_info, "[kiss]", "thread stopped\n");
}
