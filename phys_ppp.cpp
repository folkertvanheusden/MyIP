// (C) 2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
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

#include "phys_ppp.h"
#include "packet.h"
#include "utils.h"

phys_ppp::phys_ppp(stats *const s, const std::string & dev_name, const int bps, const any_addr & my_mac) : phys_slip(s, dev_name, bps, my_mac)
{
}

phys_ppp::~phys_ppp()
{
}

bool phys_ppp::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size)
{
	return 0;
}

void phys_ppp::operator()()
{
}
