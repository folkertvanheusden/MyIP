// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <string.h>

#include "ndp.h"
#include "phys.h"
#include "router.h"
#include "utils.h"


ndp::ndp(stats *const s, router *const r) : network_layer(s, "ndp", r), address_cache(s)
{
	// 1.3.6.1.2.1.4.57850.1.9: ndp
        ndp_cache_req = s->register_stat("ndp_cache_req", "1.3.6.1.2.1.4.57850.1.9.1");
        ndp_cache_hit = s->register_stat("ndp_cache_hit", "1.3.6.1.2.1.4.57850.1.9.2");

	ndp_th = new std::thread(std::ref(*this));
}

ndp::~ndp()
{
}

void ndp::add_static_entry(phys *const interface, const any_addr & mac, const any_addr & ip)
{
	update_cache(mac, ip, interface, true);
}
