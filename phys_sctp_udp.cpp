// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

// https://datatracker.ietf.org/doc/html/rfc6951

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
#include "phys_sctp_udp.h"
#include "utils.h"


// port is usually 9899
phys_sctp_udp::phys_sctp_udp(const size_t dev_index, stats *const s, const any_addr & my_mac, const any_addr & my_addr, const int port) : phys(dev_index, s), my_mac(my_mac), my_addr(my_addr)
{
	fd = create_datagram_socket(port);

	th = new std::thread(std::ref(*this));
}

phys_sctp_udp::~phys_sctp_udp()
{
	close(fd);
}

bool phys_sctp_udp::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size)
{
	DOLOG(ll_debug, "phys_sctp_udp: transmit packet (%zu bytes) %s -> %s\n", pl_size, src_mac.to_str().c_str(), dst_mac.to_str().c_str());

	stats_add_counter(phys_ifOutOctets, pl_size);
	stats_add_counter(phys_ifHCOutOctets, pl_size);
	stats_inc_counter(phys_ifOutUcastPkts);

	size_t header_size = (pl_size ? payload[0] & 0x0f : 0) * 4;

	if (pl_size < header_size) {
		DOLOG(ll_error, "phys_sctp_udp: packet is unexpectedly small (%zu bytes)\n", pl_size);

		return false;
	}

	bool ok = true;

	// collect IP addresses from original IP-header
	sockaddr_in to { 0 };
	to.sin_family      = AF_INET;
	to.sin_addr.s_addr = htonl((payload[16] << 24) | (payload[17] << 16) | (payload[18] << 8) | payload[19]);
	to.sin_port        = htons(9899);  // TODO: where can we obtain this value from?

	// strip ip-header(!)
	int rc = sendto(fd, &payload[header_size], pl_size - header_size, 0, reinterpret_cast<sockaddr *>(&to), sizeof to);

	if (size_t(rc) != pl_size - header_size) {
		DOLOG(ll_error, "phys_sctp_udp: problem sending packet (%d for %zu bytes)\n", rc, pl_size - header_size);

		if (rc == -1)
			DOLOG(ll_error, "phys_sctp_udp: %s\n", strerror(errno));

		ok = false;
	}

	return ok;
}

void phys_sctp_udp::operator()()
{
	DOLOG(ll_debug, "phys_sctp_udp: thread started\n");

	set_thread_name("myip-phys_sctp_udp");

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

	        struct timespec ts { 0, 0 };
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
			DOLOG(ll_warning, "clock_gettime failed: %s", strerror(errno));

		auto    host = get_host_as_text(reinterpret_cast<sockaddr *>(&addr));

		if (host.has_value() == false)
			continue;

		stats_inc_counter(phys_recv_frame);
		stats_inc_counter(phys_ifInUcastPkts);
		stats_add_counter(phys_ifInOctets, size);
		stats_add_counter(phys_ifHCInOctets, size);

		if (size < 20) {
			stats_inc_counter(phys_invl_frame);
			continue;
		}

		uint16_t ether_type = 0x0800;  // defaulting to IPv4

		auto it = prot_map.find(ether_type);
		if (it == prot_map.end()) {
			DOLOG(ll_info, "phys_sctp_udp: dropping ethernet packet with ether type %04x (= unknown) and size %d\n", ether_type, size);
			stats_inc_counter(phys_ign_frame);
			continue;
		}

		uint8_t dummy_src_mac[6] { 0, 0, 0, 0, uint8_t(addr.sin_port >> 8), uint8_t(addr.sin_port) };
		any_addr src_mac(dummy_src_mac, 6);

		DOLOG(ll_debug, "phys_sctp_udp: queing packet from %s (%s) to %s with ether type %04x and size %d\n", src_mac.to_str().c_str(), host.value().c_str(), my_mac.to_str().c_str(), ether_type, size);

		uint8_t ip_buffer[1620] { 0 };

		ip_buffer[0] = 0x45;  // IP version & length of header in 32b words
		ip_buffer[1] = 0;     // DSCP/ECN
		int total_length = size + 20;
		ip_buffer[2] = total_length >> 8;
		ip_buffer[3] = total_length;
		ip_buffer[4] = 0x00;  // identification
		ip_buffer[5] = 0x00;
		ip_buffer[6] = 0;     // flags & ...
		ip_buffer[7] = 0;     // fragment offset
		ip_buffer[8] = 63;    // TTL
		ip_buffer[9] = 132;   // SCTP
	        ip_buffer[10] = 0;    // checksum
	        ip_buffer[11] = 0;
		memcpy(&ip_buffer[12], &addr.sin_addr.s_addr, 4);  // FROM
		my_addr.get(&ip_buffer[16], 4);                    // TO (here)
		memcpy(&ip_buffer[20], buffer, size);

		packet *p = new packet(ts, src_mac, src_mac, my_mac, ip_buffer, total_length, nullptr, 0);

		it->second->queue_incoming_packet(this, p);
	}

	DOLOG(ll_info, "phys_sctp_udp: thread stopped\n");
}
