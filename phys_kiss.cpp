// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <algorithm>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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

phys_kiss::phys_kiss(const size_t dev_index, stats *const s, const std::string & dev_file, const int tty_bps, const any_addr & my_callsign) :
	phys(dev_index, s, "kiss-" + dev_file),
	my_callsign(my_callsign)
{
	fd = open(dev_file.c_str(), O_RDWR | O_NOCTTY);

	if (fd == -1)
		error_exit(true, "phys_kiss: Failed to open tty (%s)", dev_file.c_str());

	termios tty     { 0 };
	termios tty_old { 0 };

	if (tcgetattr(fd, &tty) == -1)
		error_exit(true, "phys_kiss: tcgetattr failed");

	tty_old = tty;

	speed_t speed = B9600;

	if (tty_bps == 9600) {
		// default
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

	th = new std::thread(std::ref(*this));
}

phys_kiss::~phys_kiss()
{
	close(fd);
}

bool phys_kiss::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload_in, const size_t pl_size_in)
{
	DOLOG(ll_debug, "phys_kiss::transmit_packet: %s => %s, ethertype: %04x, %zu bytes\n", src_mac.to_str().c_str(), dst_mac.to_str().c_str(), ether_type, pl_size_in);

	assert(src_mac.get_family() == any_addr::ax25);
	assert(dst_mac.get_family() == any_addr::ax25);

	ax25_packet a;
	a.set_from   (src_mac);
	a.set_to     (dst_mac);
	a.set_control(0x03);  // unnumbered information/frame
	a.set_data   (payload_in, pl_size_in);

	if (ether_type == 0x0800)
		a.set_pid(0xcc);  // ARPA Internet Protocol (IPv4)
	else if (ether_type == 0x0806)
		a.set_pid(0xcd);  // ARPA Adress Resolving Protocol (IPv4)
	else {
		DOLOG(ll_info, "phys_kiss::transmit_packet: cannot transmit ethertype %04x over AX.25\n", ether_type);
		return false;
	}

	auto     packet  = a.generate_packet();

	int      max_len = packet.second * 2 + 3;
	uint8_t *out     = reinterpret_cast<uint8_t *>(malloc(max_len));
	int      offset  = 0;

	uint8_t  cmd     = 0;
	uint8_t  channel = 0;

	assert(cmd < 16);
	assert(channel < 16);

	out[offset++] = FEND;

	escape_put(&out, &offset, (channel << 4) | cmd);

	for(size_t i=0; i<packet.second; i++)
		escape_put(&out, &offset, packet.first[i]);

	out[offset++] = FEND;

	ssize_t rc = WRITE(fd, out, offset);

	free(out);

	if (rc != offset) {
		DOLOG(ll_error, "failed writing to kiss device");

		return false;
	}

	return true;
}

void phys_kiss::operator()()
{
	DOLOG(ll_debug, "phys_kiss: thread started\n");

	set_thread_name("myip-phys_kiss");

	struct timespec ts { 0, 0 };

	struct pollfd fds[] = { { fd, POLLIN, 0 } };

	while(!stop_flag) {
		int rc = poll(fds, 1, 150);
		if (rc == -1) {
			if (errno == EINTR)
				continue;

			DOLOG(ll_error, "poll: %s", strerror(errno));
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

				DOLOG(ll_error, "failed reading from device");

				free(p);

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
					DOLOG(ll_error, "unexpected escape %02x", buffer);

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
					DOLOG(ll_warning, "clock_gettime failed: %s", strerror(errno));
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

			DOLOG(ll_debug, "port: %d, cmd: %d, len: %d\n", (p[0] >> 4) & 0x0f, cmd, len);

			if (cmd == 1)
				DOLOG(ll_debug, "TX delay: %d", p[1] * 10);
			else if (cmd == 2)
				DOLOG(ll_debug, "persistance: %d", p[1] * 256 - 1);
			else if (cmd == 3)
				DOLOG(ll_debug, "slot time: %dms", p[1] * 10);
			else if (cmd == 4)
				DOLOG(ll_debug, "txtail: %dms", p[1] * 10);
			else if (cmd == 5)
				DOLOG(ll_debug, "full duplex: %d", p[1]);
			else if (cmd == 6)
				DOLOG(ll_debug, "set hardware");
			else if (cmd == 15)
				DOLOG(ll_info, "kernel asked for shutdown");

			len--;

			if (len)
				memmove(&p[0], &p[1], len);
		}

		if (ok) {
			std::vector<uint8_t> payload_v(p, p + len);
			ax25_packet ap(payload_v);

			int pid = ap.get_pid().has_value() ? ap.get_pid().value() : -1;

			if (ap.get_valid()) {
				DOLOG(ll_info, "phys_kiss(%s -> %s): received packet of %d bytes\n",
						ap.get_from().get_any_addr().to_str().c_str(),
						ap.get_to  ().get_any_addr().to_str().c_str(),
						len);
			}

			if (ap.get_valid() && pid == 0xcc) {  // check for valid IPv4 payload
				auto payload = ap.get_data();
				int  pl_size = payload.get_n_bytes_left();

				packet *p = new packet(ts, ap.get_from().get_any_addr(), ap.get_from().get_any_addr(), ap.get_to().get_any_addr(), payload.get_bytes(pl_size), pl_size, nullptr, 0);

				auto it = prot_map.find(0x0800);
				it->second->queue_incoming_packet(this, p);
			}
			else if (pid == 0xf0) {  // usually beacons etc
				std::string payload_str = bin_to_text(p, len);

				DOLOG(ll_info, "phys_kiss(): pid %02x (%d bytes): %s\n", pid, len, payload_str.c_str());
			}
			else if (ap.get_valid() && pid == 0xcd) {  // check for valid ARP payload
				auto payload = ap.get_data();
				int  pl_size = payload.get_n_bytes_left();

				packet *p = new packet(ts, ap.get_from().get_any_addr(), ap.get_from().get_any_addr(), ap.get_to().get_any_addr(), payload.get_bytes(pl_size), pl_size, nullptr, 0);

				auto it = prot_map.find(0x0806);
				it->second->queue_incoming_packet(this, p);
			}
			else {
				DOLOG(ll_info, "phys_kiss(): don't know how to handle pid %02x (%d bytes)\n", pid, len);
			}
		}

		free(p);
	}

	DOLOG(ll_info, "phys_kiss: thread stopped\n");
}
