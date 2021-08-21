// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <stdint.h>
#include "stats.h"

class packet;
class udp;

class tcp_udp_fw
{
private:
	uint64_t *fw_n_dropped { nullptr };

public:
	tcp_udp_fw(stats *const s, udp *const u);
	virtual ~tcp_udp_fw();

	void input(const uint8_t *src_ip, int src_port, const uint8_t *dst_ip, int dst_port, packet *p);
};
