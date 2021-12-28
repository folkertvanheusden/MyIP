// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <algorithm>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "phys_ethernet.h"
#include "packet.h"
#include "utils.h"

void set_ifr_name(struct ifreq *ifr, const std::string & dev_name)
{
	size_t copy_name_n = std::min(size_t(IFNAMSIZ), dev_name.size());

	memcpy(ifr->ifr_name, dev_name.c_str(), copy_name_n);

	ifr->ifr_name[IFNAMSIZ - 1] = 0x00;
}

phys_ethernet::phys_ethernet(stats *const s, const std::string & dev_name, const int uid, const int gid) : phys(s)
{
	if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
		dolog(error, "open /dev/net/tun: %s", strerror(errno));
		exit(1);
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		dolog(error, "fcntl(FD_CLOEXEC): %s", strerror(errno));
		exit(1);
	}

	struct ifreq ifr_tap;
	memset(&ifr_tap, 0, sizeof ifr_tap);

	ifr_tap.ifr_flags = IFF_TAP | IFF_NO_PI;

	set_ifr_name(&ifr_tap, dev_name);

	if (ioctl(fd, TUNSETIFF, &ifr_tap) == -1) {
		dolog(error, "ioctl TUNSETIFF: %s", strerror(errno));
		exit(1);
	}

	// myip calcs checksums by itself
	if (ioctl(fd, TUNSETNOCSUM, 1) == -1) {
		dolog(error, "ioctl TUNSETNOCSUM: %s", strerror(errno));
		exit(1);
	}

	if (ioctl(fd, TUNSETGROUP, gid) == -1) {
		dolog(error, "ioctl TUNSETGROUP: %s", strerror(errno));
		exit(1);
	}

	if (ioctl(fd, TUNSETOWNER, uid) == -1) {
		dolog(error, "ioctl TUNSETOWNER: %s", strerror(errno));
		exit(1);
	}

	th = new std::thread(std::ref(*this));
}

phys_ethernet::~phys_ethernet()
{
	close(fd);
}

bool phys_ethernet::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size)
{
	dolog(debug, "phys_ethernet: transmit packet %s -> %s\n", src_mac.to_str().c_str(), dst_mac.to_str().c_str());

	stats_inc_counter(phys_transmit);

	size_t out_size = pl_size + 14;
	uint8_t *out = new uint8_t[out_size];

	dst_mac.get(&out[0], 6);

	src_mac.get(&out[6], 6);

	out[12] = ether_type >> 8;
	out[13] = ether_type;

	memcpy(&out[14], payload, pl_size);

	// crc32 is not included in a tap device

	bool ok = true;

	int rc = write(fd, out, out_size);

	if (size_t(rc) != out_size) {
		dolog(error, "phys_ethernet: problem sending packet (%d for %zu bytes)\n", rc, out_size);

		if (rc == -1)
			dolog(error, "phys_ethernet: %s\n", strerror(errno));

		ok = false;
	}

	delete [] out;

	return ok;
}

void phys_ethernet::operator()()
{
	dolog(debug, "phys_ethernet: thread started\n");

	set_thread_name("myip-phys_ethernet");

	struct pollfd fds[] = { { fd, POLLIN, 0 } };

	while(!stop_flag) {
		int rc = poll(fds, 1, 150);
		if (rc == -1) {
			if (errno == EINTR)
				continue;

			dolog(error, "poll: %s", strerror(errno));
			exit(1);
		}

		if (rc == 0)
			continue;

		uint8_t buffer[1600];
		int size = read(fd, (char *)buffer, sizeof buffer);

	        struct timespec ts { 0, 0 };
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
			dolog(warning, "clock_gettime failed: %s", strerror(errno));

		stats_inc_counter(phys_recv_frame);

		if (size < 14) {
			stats_inc_counter(phys_invl_frame);
			continue;
		}

		uint16_t ether_type = (buffer[12] << 8) | buffer[13];

		auto it = prot_map.find(ether_type);
		if (it == prot_map.end()) {
			dolog(info, "phys_ethernet: dropping ethernet packet with ether type %04x (= unknown) and size %d\n", ether_type, size);
			stats_inc_counter(phys_ign_frame);
			continue;
		}

		any_addr dst_mac(&buffer[0], 6);

		any_addr src_mac(&buffer[6], 6);

		dolog(debug, "phys_ethernet: queing packet from %s to %s with ether type %04x and size %d\n", src_mac.to_str().c_str(), dst_mac.to_str().c_str(), ether_type, size);

		packet *p = new packet(ts, src_mac, any_addr(&buffer[6], 6), any_addr(&buffer[0], 6), &buffer[14], size - 14, &buffer[0], 14);

		it->second->queue_packet(p);
	}

	dolog(info, "phys_ethernet: thread stopped\n");
}
