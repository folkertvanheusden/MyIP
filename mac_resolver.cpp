#include <assert.h>

#include "log.h"
#include "mac_resolver.h"


constexpr size_t pkts_max_size { 256 };

mac_resolver::mac_resolver(stats *const s, router *const r) : network_layer(s, "mac-resolver", r)
{
	pkts = new fifo<fifo_element_t>(s, "arp", pkts_max_size);
}

mac_resolver::~mac_resolver()
{
	delete pkts;
}

any_addr mac_resolver::get_addr() const
{
	assert(0);
}

void mac_resolver::queue_incoming_packet(phys *const interface, const packet *p)
{
	if (pkts->try_put({ interface, p }) == false) {
		DOLOG(ll_debug, "mac_resolver: packet dropped\n");

		delete p;
	}
}

bool mac_resolver::transmit_packet(const std::optional<any_addr> & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) 
{
	assert(0);

	return false;
}

int mac_resolver::get_max_packet_size() const
{
	assert(0);

	return -1;
}
