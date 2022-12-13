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

#include "log.h"
#include "phys_slip.h"
#include "packet.h"
#include "utils.h"


phys_slip::phys_slip(const size_t dev_index, stats *const s, const std::string & dev_name, const int bps, const any_addr & my_mac) :
	phys(dev_index, s, "slip-" + dev_name),
	my_mac(my_mac)
{
	assert(my_mac.get_len() == 6);

	if ((fd = open(dev_name.c_str(), O_RDWR)) == -1) {
		DOLOG(ll_error, "open %s: %s", dev_name.c_str(), strerror(errno));
		exit(1);
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		DOLOG(ll_error, "fcntl(FD_CLOEXEC): %s", strerror(errno));
		exit(1);
	}

        struct termios tty;
        if (tcgetattr(fd, &tty) != 0) {
		DOLOG(ll_error, "tcgetattr: %s", strerror(errno));
		exit(1);
        }

        cfsetospeed(&tty, bps);
        cfsetispeed(&tty, bps);

        tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;     // 8-bit chars
        tty.c_iflag &= ~IGNBRK;         // disable break processing
        tty.c_lflag = 0;                // no signaling chars, no echo,
                                        // no canonical processing
        tty.c_oflag = 0;                // no remapping, no delays
        tty.c_cc[VMIN]  = 1;            // read blocks
        tty.c_cc[VTIME] = 127;            // 12.7 seconds read timeout

        tty.c_iflag &= ~(IXON | IXOFF | IXANY); // shut off xon/xoff ctrl

        tty.c_cflag |= (CLOCAL | CREAD);// ignore modem controls,
                                        // enable reading
        tty.c_cflag &= ~(PARENB | PARODD);      // shut off parity
        tty.c_cflag &= ~CSTOPB;
        tty.c_cflag &= ~CRTSCTS;

        if (tcsetattr(fd, TCSANOW, &tty) != 0) {
		DOLOG(ll_error, "tcsetattr: %s", strerror(errno));
		exit(1);
        }
}

phys_slip::~phys_slip()
{
	close(fd);
}

void phys_slip::start()
{
	th = new std::thread(std::ref(*this));
}

bool phys_slip::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size)
{
	DOLOG(ll_debug, "phys_slip: transmit packet %s -> %s\n", src_mac.to_str().c_str(), dst_mac.to_str().c_str());

	size_t out_size = pl_size * 2 + 2;
	uint8_t *out = new uint8_t[out_size];

	size_t out_o = 0;
	out[out_o++] = 0xc0;  // END
	for(size_t i=0; i<pl_size; i++) {
		if (payload[i] == 0xc0) {
			out[out_o++] = 0xdb;
			out[out_o++] = 0xdc;
		}
		else if (payload[i] == 0xdb) {
			out[out_o++] = 0xdb;
			out[out_o++] = 0xdd;
		}
		else {
			out[out_o++] = payload[i];
		}
	}
	out[out_o++] = 0xc0;  // END

	stats_add_counter(phys_ifOutOctets, out_o);
	stats_add_counter(phys_ifHCOutOctets, out_o);
	stats_inc_counter(phys_ifOutUcastPkts);

	bool ok = true;

	int rc = write(fd, out, out_o);

	if (size_t(rc) != out_o) {
		DOLOG(ll_error, "phys_slip: problem sending packet (%d for %zu bytes)\n", rc, out_o);

		if (rc == -1)
			DOLOG(ll_error, "phys_slip: %s\n", strerror(errno));

		ok = false;
	}

	delete [] out;

	return ok;
}

void phys_slip::operator()()
{
	DOLOG(ll_debug, "phys_slip: thread started\n");

	set_thread_name("myip-phys_slip");

	std::vector<uint8_t> packet_buffer;

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

		uint8_t buffer = 0x00;
		int size = read(fd, (char *)&buffer, 1);
		if (size == -1)
			continue;

		stats_add_counter(phys_ifInOctets, size);
		stats_add_counter(phys_ifHCInOctets, size);
		stats_inc_counter(phys_ifInUcastPkts);

		if (buffer == 0xdb) {
			uint8_t buffer2 = 0x00;
			read(fd, (char *)&buffer2, 1);

			if (buffer2 == 0xdc)  // escape for 'END'
				packet_buffer.push_back(0xc0);
			else if (buffer2 == 0xdd)  // escape for 'ESCAPE'
				packet_buffer.push_back(0xdb);
		}
		else if (buffer == 0xc0) {  // END of packet
			stats_inc_counter(phys_recv_frame);

			if (packet_buffer.size() < 20) {
				DOLOG(ll_debug, "phys_slip: invalid packet, size %zu\n", packet_buffer.size());

				if (size)
					stats_inc_counter(phys_invl_frame);

				packet_buffer.clear();

				continue;
			}

			any_addr src_mac(any_addr::mac, (const uint8_t *)"\0\0\0\0\0\1");

			DOLOG(ll_debug, "phys_slip: queing packet, size %zu\n", packet_buffer.size());

			auto it = prot_map.find(0x800);  // assuming IPv4
			if (it == prot_map.end())
				DOLOG(ll_warning, "phys_slip: no IPv4 stack attached to SLIP device (yet)\n");
			else {
				packet *p = new packet(src_mac, my_mac, packet_buffer.data(), packet_buffer.size(), NULL, 0);

				it->second->queue_incoming_packet(this, p);
			}

			packet_buffer.clear();
		}
		else {
			packet_buffer.push_back(buffer);
		}
	}

	DOLOG(ll_info, "phys_slip: thread stopped\n");
}
