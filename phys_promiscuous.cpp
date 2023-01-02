// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <algorithm>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "log.h"
#include "phys_promiscuous.h"
#include "packet.h"
#include "str.h"
#include "utils.h"


phys_promiscuous::phys_promiscuous(const size_t dev_index, stats *const s, const std::string & dev_name) :
	phys(dev_index, s, "promiscuous-" + dev_name)
{
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd == -1)
		error_exit(true, "phys_promiscuous: cannot create raw socket");

	const size_t if_name_len = dev_name.size();

	struct ifreq ifr { 0 };
	if (if_name_len >= sizeof(ifr.ifr_name))
		error_exit(false, "phys_promiscuous: device name too long");

	memcpy(ifr.ifr_name, dev_name.c_str(), if_name_len);

	if (ioctl(fd, SIOCGIFMTU, &ifr) == -1)
		error_exit(true, "phys_promiscuous: ioctl(SIOCGIFMTU) failed");

	mtu_size = ifr.ifr_mtu;
	DOLOG(ll_debug, "phys_promiscuous: MTU size: %d\n", mtu_size);

	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
		error_exit(true, "phys_promiscuous: ioctl(SIOCGIFINDEX) failed");

	struct sockaddr_ll sa { 0 };
	sa.sll_family   = PF_PACKET;
	sa.sll_protocol = 0x0000;
	sa.sll_ifindex  = ifr.ifr_ifindex;
	sa.sll_hatype   = 0;
	sa.sll_pkttype  = PACKET_HOST;

	if (bind(fd, reinterpret_cast<const struct sockaddr *>(&sa), sizeof sa) == -1)
		error_exit(true, "phys_promiscuous: bind failed");

	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev_name.c_str(), dev_name.size()) == -1)
		error_exit(true, "phys_promiscuous: setsockopt(SO_BINDTODEVICE) failed");

	ifr_index = ifr.ifr_ifindex;

	th = new std::thread(std::ref(*this));
}

phys_promiscuous::~phys_promiscuous()
{
	close(fd);
}

bool phys_promiscuous::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size)
{
	DOLOG(ll_debug, "phys_promiscuous: transmit packet %s -> %s\n", src_mac.to_str().c_str(), dst_mac.to_str().c_str());

	size_t   out_size = pl_size + 14;
	uint8_t *out      = new uint8_t[out_size];

	dst_mac.get(&out[0], 6);

	src_mac.get(&out[6], 6);

	out[12] = ether_type >> 8;
	out[13] = ether_type;

	memcpy(&out[14], payload, pl_size);

	stats_add_counter(phys_ifOutOctets, out_size);
	stats_add_counter(phys_ifHCOutOctets, out_size);
	stats_inc_counter(phys_ifOutUcastPkts);

	bool ok = true;

	struct sockaddr_ll socket_address { 0 };
	socket_address.sll_ifindex = ifr_index;
	socket_address.sll_halen   = ETH_ALEN;
	src_mac.get(socket_address.sll_addr, 6);

	int rc = write(fd, out, out_size);

	if (size_t(rc) != out_size) {
		DOLOG(ll_error, "phys_promiscuous: problem sending packet (%d for %zu bytes)\n", rc, out_size);

		if (rc == -1)
			DOLOG(ll_error, "phys_promiscuous: %s\n", strerror(errno));

		ok = false;
	}

	delete [] out;

	return ok;
}

void phys_promiscuous::operator()()
{
	DOLOG(ll_debug, "phys_promiscuous: thread started\n");

	set_thread_name("myip-phys_promiscuous");

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

		int size = read(fd, reinterpret_cast<char *>(buffer), mtu_size);

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
			DOLOG(ll_info, "phys_promiscuous: dropping ethernet packet with ether type %04x (= unknown) and size %d\n", ether_type, size);
			stats_inc_counter(phys_ign_frame);
			continue;
		}

		any_addr dst_mac(any_addr::mac, &buffer[0]);

		any_addr src_mac(any_addr::mac, &buffer[6]);

		DOLOG(ll_debug, "phys_promiscuous: queing packet from %s to %s with ether type %04x and size %d\n", src_mac.to_str().c_str(), dst_mac.to_str().c_str(), ether_type, size);

		std::string log_prefix = myformat("PRM[%02x%02x%02x%02x%02x%02x]", buffer[6], buffer[7], buffer[8], buffer[9], buffer[10], buffer[11]);

		packet *p = new packet(ts, src_mac, src_mac, dst_mac, &buffer[14], size - 14, &buffer[0], 14, log_prefix);

		it->second->queue_incoming_packet(this, p);
	}

	delete [] buffer;

	DOLOG(ll_info, "phys_promiscuous: thread stopped\n");
}
