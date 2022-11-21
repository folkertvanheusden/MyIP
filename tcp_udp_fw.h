// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <stdint.h>

#include "any_addr.h"
#include "stats.h"
#include "types.h"


class packet;
class udp;

class tcp_udp_fw
{
private:
	uint64_t *fw_n_dropped { nullptr };

public:
	tcp_udp_fw(stats *const s, udp *const u);
	virtual ~tcp_udp_fw();

	void input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, session_data *const pd);
};
