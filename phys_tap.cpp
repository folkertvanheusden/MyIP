// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <algorithm>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "log.h"
#include "phys_tap.h"
#include "packet.h"
#include "str.h"
#include "utils.h"


void set_ifr_name(struct ifreq *ifr, const std::string & dev_name)
{
	size_t copy_name_n = std::min(size_t(IFNAMSIZ), dev_name.size());

	memcpy(ifr->ifr_name, dev_name.c_str(), copy_name_n);

	ifr->ifr_name[copy_name_n] = 0x00;
}

phys_tap::phys_tap(const size_t dev_index, stats *const s, const std::string & dev_name, const int uid, const int gid, const int mtu_size) :
	phys(dev_index, s, "tap-" + dev_name)
{
	if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
		DOLOG(ll_error, "open /dev/net/tun: %s", strerror(errno));
		exit(1);
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		DOLOG(ll_error, "fcntl(FD_CLOEXEC): %s", strerror(errno));
		exit(1);
	}

	this->mtu_size = mtu_size;

	struct ifreq ifr_tap1 { 0 };

	ifr_tap1.ifr_flags = IFF_TAP | IFF_NO_PI;

	set_ifr_name(&ifr_tap1, dev_name);

	if (ioctl(fd, TUNSETIFF, &ifr_tap1) == -1) {
		DOLOG(ll_error, "ioctl TUNSETIFF: %s\n", strerror(errno));
		exit(1);
	}

	// myip calcs checksums by itself
	if (ioctl(fd, TUNSETNOCSUM, 1) == -1) {
		DOLOG(ll_error, "ioctl TUNSETNOCSUM: %s\n", strerror(errno));
		exit(1);
	}

	if (ioctl(fd, TUNSETGROUP, gid) == -1) {
		DOLOG(ll_error, "ioctl TUNSETGROUP: %s\n", strerror(errno));
		exit(1);
	}

	if (ioctl(fd, TUNSETOWNER, uid) == -1) {
		DOLOG(ll_error, "ioctl TUNSETOWNER: %s\n", strerror(errno));
		exit(1);
	}

	int fd_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	struct ifreq ifr_tap2 { 0 };

	set_ifr_name(&ifr_tap2, dev_name);

	ifr_tap2.ifr_addr.sa_family = AF_INET;
	ifr_tap2.ifr_mtu            = mtu_size;

	if (ioctl(fd_sock, SIOCSIFMTU, &ifr_tap2) == -1) {
		DOLOG(ll_error, "ioctl SIOCSIFMTU(%d): %s\n", mtu_size, strerror(errno));
		exit(1);
	}

	close(fd_sock);

	th = new std::thread(std::ref(*this));
}

phys_tap::~phys_tap()
{
	close(fd);
}

bool phys_tap::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size)
{
	DOLOG(ll_debug, "phys_tap(%s): transmit packet %s -> %s\n", name.c_str(), src_mac.to_str().c_str(), dst_mac.to_str().c_str());

	size_t out_size = pl_size + 14;

	if (out_size < 64)
		out_size = 64;

	uint8_t *out = new uint8_t[out_size]();

	dst_mac.get(&out[0], 6);

	src_mac.get(&out[6], 6);

	out[12] = ether_type >> 8;
	out[13] = ether_type;

	memcpy(&out[14], payload, pl_size);

	// crc32 is not included in a tap device

	stats_add_counter(phys_ifOutOctets,   out_size);
	stats_add_counter(phys_ifHCOutOctets, out_size);
	stats_inc_counter(phys_ifOutUcastPkts);

	bool ok = true;

	int rc = write(fd, out, out_size);

	if (size_t(rc) != out_size) {
		DOLOG(ll_error, "phys_tap: problem sending packet (%d for %zu bytes)\n", rc, out_size);

		if (rc == -1)
			DOLOG(ll_error, "phys_tap: %s\n", strerror(errno));

		ok = false;
	}

	delete [] out;

	return ok;
}

void phys_tap::operator()()
{
	DOLOG(ll_debug, "phys_tap: thread started\n");

	set_thread_name("myip-phys_tap");

	struct pollfd fds[] = { { fd, POLLIN, 0 } };

	uint8_t *buffer = new uint8_t[mtu_size];

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

		int size = read(fd, (char *)buffer, mtu_size);

	        struct timespec ts { 0, 0 };
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
			DOLOG(ll_warning, "clock_gettime failed: %s", strerror(errno));

		stats_inc_counter(phys_recv_frame);
		stats_inc_counter(phys_ifInUcastPkts);
		stats_add_counter(phys_ifInOctets, size);
		stats_add_counter(phys_ifHCInOctets, size);

		if (size < 14) {
			stats_inc_counter(phys_invl_frame);
			continue;
		}

		uint16_t ether_type = (buffer[12] << 8) | buffer[13];

		auto it = prot_map.find(ether_type);
		if (it == prot_map.end()) {
			DOLOG(ll_info, "phys_tap(%s): dropping ethernet packet with ether type %04x (= unknown) and size %d\n", name.c_str(), ether_type, size);
			stats_inc_counter(phys_ign_frame);
			continue;
		}

		any_addr dst_mac(any_addr::mac, &buffer[0]);

		any_addr src_mac(any_addr::mac, &buffer[6]);

		DOLOG(ll_debug, "phys_tap(%s): queing packet from %s to %s with ether type %04x and size %d\n", name.c_str(), src_mac.to_str().c_str(), dst_mac.to_str().c_str(), ether_type, size);

		std::string log_prefix = myformat("PRM[%02x%02x%02x%02x%02x%02x]", buffer[6], buffer[7], buffer[8], buffer[9], buffer[10], buffer[11]);

		packet *p = new packet(ts, src_mac, src_mac, dst_mac, &buffer[14], size - 14, &buffer[0], 14, log_prefix);

		it->second->queue_incoming_packet(this, p);
	}

	delete [] buffer;

	DOLOG(ll_info, "phys_tap: thread stopped\n");
}
