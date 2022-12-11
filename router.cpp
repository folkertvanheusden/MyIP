#include <assert.h>
#include <map>
#include <thread>

#include "any_addr.h"
#include "arp.h"
#include "phys.h"
#include "router.h"


constexpr size_t pkts_max_size { 256 };

router::router(stats *const s)
{
	pkts = new fifo<queued_packet *>(s, "router", pkts_max_size);

	router_th = new std::thread(std::ref(*this));
}

router::~router()
{
	stop_flag = true;

	router_th->join();
	delete router_th;

	delete pkts;
}

void router::add_router_ipv4(const any_addr & network, const uint8_t netmask[4], phys *const interface, arp *const iarp)
{
	assert(network.get_family() == any_addr::ipv4);

	router_entry re;

	re.network_address      = network;
	re.mask.ipv4_netmask[0] = netmask[0];
	re.mask.ipv4_netmask[1] = netmask[1];
	re.mask.ipv4_netmask[2] = netmask[2];
	re.mask.ipv4_netmask[3] = netmask[3];
	re.interface            = interface;
	re.mac_lookup.iarp      = iarp;

	std::unique_lock<std::shared_mutex> lck(table_lock);
	table.push_back(re);
}

bool router::route_packet(const std::optional<any_addr> & override_dst_mac, const uint16_t ether_type, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t *const payload, const size_t pl_size)
{
	queued_packet *qp = new queued_packet(payload, pl_size);

	qp->ether_type = ether_type;

	assert(override_dst_mac.has_value() == false || override_dst_mac.value().get_family() == any_addr::mac);
	qp->dst_mac    = override_dst_mac;

	assert(dst_ip.get_family() == any_addr::ipv4 || dst_ip.get_family() == any_addr::ipv6);
	qp->dst_ip     = dst_ip;

	assert(src_ip.get_family() == any_addr::ipv4 || src_ip.get_family() == any_addr::ipv6);
	qp->src_ip     = src_ip;

	return pkts->try_put(qp);
}

void router::operator()()
{
	while(!stop_flag) {
		auto po = pkts->get(500);
		if (!po.has_value())
			continue;

		router_entry *re = nullptr;

		std::shared_lock<std::shared_mutex> lck(table_lock);

		for(auto & entry : table) {
			if (entry.network_address.get_family() != po.value()->src_ip.get_family())
				continue;

			if (entry.network_address.get_family() == any_addr::ipv4) {
				bool match = true;

				for(int i=0; i<4; i++) {
					if ((po.value()->dst_ip[i] & entry.mask.ipv4_netmask[i]) != entry.network_address[i]) {
						match = false;
						break;
					}
				}

				if (match) {
					// route through this
					re = &entry;
					break;
				}
			}
			else if (entry.network_address.get_family() == any_addr::ipv6) {
			}
			else {
				DOLOG(ll_warning, "Unknown address family in queued packet (%d)\n", entry.network_address.get_family());
			}
		}

		if (!re) {
			DOLOG(ll_debug, "No route for packet\n");
			continue;
		}

		if (po.value()->src_mac.has_value() == false) {
			// TODO lookup src MAC address
			// TODO arp - should be statically stored -> depending on outgoing interface

			if (re->network_address.get_family() == any_addr::ipv4) {
				po.value()->src_mac = re->mac_lookup.iarp->get_mac(po.value()->src_ip);
			}
			else {
				// TODO: ipv6
			}
		}

		if (po.value()->dst_mac.has_value() == false) {
			if (re->network_address.get_family() == any_addr::ipv4) {
				po.value()->dst_mac = re->mac_lookup.iarp->get_mac(po.value()->dst_ip);
			}
			else {
				// TODO: ipv6
			}
		}

		if (po.value()->src_mac.has_value() && po.value()->dst_mac.has_value()) {
			if (!re->interface->transmit_packet(po.value()->dst_mac.value(), po.value()->src_mac.value(), po.value()->ether_type, po.value()->data, po.value()->data_len)) {
				DOLOG(ll_debug, "Cannot transmit_packet\n");
			}
		}
		else {
			// TODO log
		}

		delete po.value();
	}
}
