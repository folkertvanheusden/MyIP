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

void tcp_udp_fw::input(const uint8_t *src_ip, int src_port, const uint8_t *dst_ip, int dst_port, packet *p)
{
	// silently drop
	stats_inc_counter(fw_n_dropped);
}
