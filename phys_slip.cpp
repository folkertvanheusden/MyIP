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
#include "tty.h"
#include "utils.h"


phys_slip::phys_slip(const size_t dev_index, stats *const s, const std::string & dev_name, const int bps, const any_addr & my_mac) :
	phys(dev_index, s, "slip-" + dev_name),
	my_mac(my_mac)
{
	assert(my_mac.get_len() == 6);

	fd = open_tty(dev_name, bps);
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
	CDOLOG(ll_debug, "[slip]", "transmit packet %s -> %s\n", src_mac.to_str().c_str(), dst_mac.to_str().c_str());

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
		CDOLOG(ll_error, "[slip]", "problem sending packet (%d for %zu bytes)\n", rc, out_o);

		if (rc == -1)
			CDOLOG(ll_error, "[slip]", "%s\n", strerror(errno));

		ok = false;
	}

	delete [] out;

	return ok;
}

void phys_slip::operator()()
{
	CDOLOG(ll_debug, "[slip]", "thread started\n");

	set_thread_name("myip-phys_slip");

	std::vector<uint8_t> packet_buffer;

	struct pollfd fds[] = { { fd, POLLIN, 0 } };

	struct timespec ts { 0, 0 };

	while(!stop_flag) {
		int rc = poll(fds, 1, 150);
		if (rc == -1) {
			if (errno == EINTR)
				continue;

			CDOLOG(ll_error, "[slip]", "poll: %s", strerror(errno));
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

		if (packet_buffer.empty()) {
			if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
				CDOLOG(ll_warning, "[slip]", "clock_gettime failed: %s", strerror(errno));
		}

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
				CDOLOG(ll_debug, "[slip]", "invalid packet, size %zu\n", packet_buffer.size());

				if (size)
					stats_inc_counter(phys_invl_frame);

				packet_buffer.clear();

				continue;
			}

			any_addr src_mac(any_addr::mac, (const uint8_t *)"\0\0\0\0\0\1");

			CDOLOG(ll_debug, "[slip]", "queing packet, size %zu\n", packet_buffer.size());

			auto it = prot_map.find(0x800);  // assuming IPv4
			if (it == prot_map.end())
				CDOLOG(ll_warning, "[slip]", "no IPv4 stack attached to SLIP device (yet)\n");
			else {
				packet *p = new packet(ts, src_mac, my_mac, packet_buffer.data(), packet_buffer.size(), NULL, 0, "SLIP[]");

				it->second->queue_incoming_packet(this, p);
			}

			packet_buffer.clear();
		}
		else {
			packet_buffer.push_back(buffer);
		}
	}

	CDOLOG(ll_info, "[slip]", "thread stopped\n");
}
