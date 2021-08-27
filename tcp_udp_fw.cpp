// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <arpa/inet.h>
#include <sys/time.h>

#include "tcp_udp_fw.h"
#include "udp.h"

tcp_udp_fw::tcp_udp_fw(stats *const s, udp *const u)
{
	fw_n_dropped = s->register_stat("fw_n_dropped");
}

tcp_udp_fw::~tcp_udp_fw()
{
}

void tcp_udp_fw::input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, void *const pd)
{
	// silently drop
	stats_inc_counter(fw_n_dropped);
}
