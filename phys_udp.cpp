// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <algorithm>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "log.h"
#include "net.h"
#include "packet.h"
#include "phys_udp.h"
#include "utils.h"


// port is usually 9899
phys_udp::phys_udp(const size_t dev_index, stats *const s, const any_addr & my_mac, const int port) : phys(dev_index, s), my_mac(my_mac)
{
	fd = create_datagram_socket(port);

	th = new std::thread(std::ref(*this));
}

phys_udp::~phys_udp()
{
	close(fd);
}

bool phys_udp::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size)
{
	DOLOG(debug, "phys_udp: transmit packet %s -> %s\n", src_mac.to_str().c_str(), dst_mac.to_str().c_str());

	stats_add_counter(phys_ifOutOctets, pl_size);
	stats_add_counter(phys_ifHCOutOctets, pl_size);
	stats_inc_counter(phys_ifOutUcastPkts);

	bool ok = true;

	int rc = write(fd, payload, pl_size);

	if (size_t(rc) != pl_size) {
		DOLOG(ll_error, "phys_udp: problem sending packet (%d for %zu bytes)\n", rc, pl_size);

		if (rc == -1)
			DOLOG(ll_error, "phys_udp: %s\n", strerror(errno));

		ok = false;
	}

	return ok;
}

void phys_udp::operator()()
{
	DOLOG(debug, "phys_udp: thread started\n");

	set_thread_name("myip-phys_udp");

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

		uint8_t     buffer[1600] { 0 };
		sockaddr_in addr         { 0 };
		socklen_t   addr_len     { sizeof addr };

		ssize_t size = recvfrom(fd, buffer, sizeof buffer, 0, reinterpret_cast<struct sockaddr *>(&addr), &addr_len);

		auto    host = get_host_as_text(addr);

		if (host.has_value() == false)
			continue;

		{
			std::unique_lock<std::mutex> lck(peers_lock);

			auto it = peers.find(host);

			if (it == peers.end())
				peers.insert({ host, addr });
		}

	        struct timespec ts { 0, 0 };
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
			DOLOG(warning, "clock_gettime failed: %s", strerror(errno));

		stats_inc_counter(phys_recv_frame);
		stats_inc_counter(phys_ifInUcastPkts);
		stats_add_counter(phys_ifInOctets, size);
		stats_add_counter(phys_ifHCInOctets, size);

		if (size < 14) {
			stats_inc_counter(phys_invl_frame);
			continue;
		}

		uint16_t ether_type = 0x0800;  // defaulting to IPv4

		auto it = prot_map.find(ether_type);
		if (it == prot_map.end()) {
			DOLOG(info, "phys_udp: dropping ethernet packet with ether type %04x (= unknown) and size %d\n", ether_type, size);
			stats_inc_counter(phys_ign_frame);
			continue;
		}

		uint8_t dummy_src_mac[6] { 0, 0, 0, 0, uint8_t(addr.sin_port >> 16), uint8_t(addr.sin_port) };
		any_addr src_mac(dummy_src_mac, 6);

		DOLOG(debug, "phys_udp: queing packet from %s to %s with ether type %04x and size %d\n", src_mac.to_str().c_str(), my_mac.to_str().c_str(), ether_type, size);

		packet *p = new packet(ts, src_mac, src_mac, my_mac, buffer, size, nullptr, 0);

		it->second->queue_packet(this, p);
	}

	DOLOG(info, "phys_udp: thread stopped\n");
}
