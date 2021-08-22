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

#include "phys.h"
#include "packet.h"
#include "utils.h"

void set_ifr_name(struct ifreq *ifr, const std::string & dev_name)
{
	size_t copy_name_n = std::min(size_t(IFNAMSIZ), dev_name.size());

	memcpy(ifr->ifr_name, dev_name.c_str(), copy_name_n);

	ifr->ifr_name[IFNAMSIZ - 1] = 0x00;
}

phys::phys(stats *const s, const std::string & dev_name)
{
	if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
		perror("open /dev/net/tun");
		exit(1);
	}

	struct ifreq ifr_tap;
	memset(&ifr_tap, 0, sizeof ifr_tap);

	ifr_tap.ifr_flags = IFF_TAP | IFF_NO_PI;

	set_ifr_name(&ifr_tap, dev_name);

	if (ioctl(fd, TUNSETIFF, &ifr_tap) == -1) {
		perror("ioctl TUNSETIFF");
		close(fd);
		exit(1);
	}

	phys_recv_frame = s->register_stat("phys_recv_frame");
	phys_invl_frame = s->register_stat("phys_invl_frame");
	phys_ign_frame = s->register_stat("phys_ign_frame");
	phys_transmit = s->register_stat("phys_transmit");

	// MTU size for Ethernet
	mtu_size = 1500;
	dolog("phys: MTU size: %d\n", mtu_size);

	th = new std::thread(std::ref(*this));
}

phys::~phys()
{
	close(fd);

	stop_flag = true;

	th->join();
	delete th;
}

void phys::register_protocol(const uint16_t ether_type, protocol *const p)
{
	// FIXME prot-map write lock
	prot_map.insert({ ether_type, p });

	p->register_phys(this);
}

void phys::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size)
{
	dolog("phys: transmit packet %s -> %s\n", src_mac.to_str().c_str(), dst_mac.to_str().c_str());

	stats_inc_counter(phys_transmit);

	size_t out_size = pl_size + 14;
	uint8_t *out = new uint8_t[out_size];

	dst_mac.get(&out[0], 6);

	src_mac.get(&out[6], 6);

	out[12] = ether_type >> 8;
	out[13] = ether_type;

	memcpy(&out[14], payload, pl_size);

	// crc32 is not included in a tap device

	int rc = write(fd, out, out_size);

	if (size_t(rc) != out_size) {
		dolog("phys: problem sending packet (%d for %zu bytes)\n", rc, out_size);

		if (rc == -1)
			dolog("phys: %s\n", strerror(errno));
	}

	delete [] out;
}

void phys::operator()()
{
	dolog("phys: thread started\n");

	set_thread_name("phys");

	struct pollfd fds[] = { { fd, POLLIN, 0 } };

	while(!stop_flag) {
		int rc = poll(fds, 1, 150);
		if (rc == -1) {
			if (errno == EINTR)
				continue;

			perror("poll");
			exit(1);
		}

		if (rc == 0)
			continue;

		uint8_t buffer[1600];
		int size = read(fd, (char *)buffer, sizeof buffer);

		struct timeval tv { 0, 0 };
		gettimeofday(&tv, nullptr);

		stats_inc_counter(phys_recv_frame);

		if (size < 14) {
			stats_inc_counter(phys_invl_frame);
			continue;
		}

		uint16_t ether_type = (buffer[12] << 8) | buffer[13];

		// FIXME prot_map read lock
		auto it = prot_map.find(ether_type);
		if (it == prot_map.end()) {
			dolog("phys: dropping ethernet packet with ether type %04x (= unknown) and size %d\n", ether_type, size);
			stats_inc_counter(phys_ign_frame);
			continue;
		}

		dolog("phys: queing packet with ether type %04x and size %d\n", ether_type, size);

		packet *p = new packet(tv, any_addr(&buffer[6], 6), any_addr(&buffer[0], 6), &buffer[14], size - 14, &buffer[0], 14);

		it->second->queue_packet(p);
	}

	dolog("phys: thread stopped\n");
}
