#include <assert.h>
#include <map>
#include <thread>

#include "any_addr.h"
#include "arp.h"
#include "ndp.h"
#include "phys.h"
#include "router.h"


constexpr size_t pkts_max_size { 256 };

router::router(stats *const s, const int n_threads)
{
	pkts = new fifo<queued_packet *>(s, "router", pkts_max_size);

	for(int i=0; i<n_threads; i++) {
		std::thread *th = new std::thread(std::ref(*this));
		assert(th);
		router_ths.push_back(th);
	}
}

router::~router()
{
	stop_flag = true;

	for(auto th : router_ths) {
		th->join();

		delete th;
	}

	delete pkts;
}

void router::stop()
{
	stop_flag = true;
}

bool check_subnet(const any_addr & addr, const any_addr & network, const int cidr)
{
	uint8_t addr_bytes[16] { 0 };
	addr.get(addr_bytes, sizeof addr_bytes);

	uint8_t network_bytes[16] { 0 };
	network.get(network_bytes, sizeof network_bytes);

	int n_bytes = cidr / 8;

	if (std::equal(addr_bytes, addr_bytes + n_bytes, network_bytes) == false)
		return false;

	int n_bits = cidr & 7;

	if (n_bits) {
		int mask = 0xff << (8 - n_bits);

		if ((addr_bytes[n_bytes] & mask) != (network_bytes[n_bytes] & mask))
			return false;
	}

	return true;
}

void router::add_router_ipv4(const any_addr & network, const uint8_t netmask[4], const std::optional<any_addr> & gateway, phys *const interface, arp *const iarp)
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
	re.default_gateway      = gateway;

	std::unique_lock<std::shared_mutex> lck(table_lock);
	table.push_back(re);
}

void router::add_router_ipv6(const any_addr & network, const int cidr, phys *const interface, ndp *const indp)
{
	assert(network.get_family() == any_addr::ipv6);

	router_entry re;

	re.network_address         = network;
	re.mask.ipv6_prefix_length = cidr;
	re.interface               = interface;
	re.mac_lookup.indp         = indp;

	std::unique_lock<std::shared_mutex> lck(table_lock);
	table.push_back(re);
}

bool router::route_packet(const std::optional<any_addr> & override_dst_mac, const uint16_t ether_type, const any_addr & dst_ip, const any_addr & src_mac, const any_addr & src_ip, const uint8_t *const payload, const size_t pl_size)
{
	queued_packet *qp = new queued_packet(payload, pl_size);

	qp->ether_type = ether_type;

	assert(override_dst_mac.has_value() == false || override_dst_mac.value().get_family() == any_addr::mac);
	qp->dst_mac    = override_dst_mac;

	qp->src_mac    = src_mac;

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
				// TODO move into a function
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
				if (check_subnet(po.value()->src_ip, entry.network_address, entry.mask.ipv6_prefix_length))
					re = &entry;
			}
			else {
				DOLOG(ll_warning, "router::operator: unknown address family in queued packet (%d)\n", entry.network_address.get_family());
			}
		}

		if (!re) {
			DOLOG(ll_debug, "router::operator: no route for packet\n");
			continue;
		}

		if (po.value()->src_mac.has_value() == false) {
			if (re->network_address.get_family() == any_addr::ipv4) {
				// must always succeed, see main where a static rarp is setup
				po.value()->src_mac = re->mac_lookup.iarp->get_mac(re->interface, po.value()->src_ip);
			}
			else {
				po.value()->src_mac = re->mac_lookup.indp->get_mac(re->interface, po.value()->src_ip);
			}
		}

		if (po.value()->dst_mac.has_value() == false) {
			if (re->network_address.get_family() == any_addr::ipv4) {
				DOLOG(ll_debug, "router::operator: ARPing MAC for %s\n", po.value()->dst_ip.to_str().c_str());

				po.value()->dst_mac = re->mac_lookup.iarp->get_mac(re->interface, po.value()->dst_ip);
			}
			else {
				DOLOG(ll_debug, "router::operator: NDPing MAC for %s\n", po.value()->dst_ip.to_str().c_str());

				po.value()->dst_mac = re->mac_lookup.indp->get_mac(re->interface, po.value()->dst_ip);
			}

			// not found? try the default gateway
			if (po.value()->dst_mac.has_value() == false && re->default_gateway.has_value()) {
				DOLOG(ll_debug, "router::operator: MAC for %s not found, resolving default gateway (%s)\n", po.value()->dst_ip.to_str().c_str(), re->default_gateway.value().to_str().c_str());

				if (re->network_address.get_family() == any_addr::ipv4)
					po.value()->dst_mac = re->mac_lookup.iarp->get_mac(re->interface, re->default_gateway.value());
				else
					po.value()->dst_mac = re->mac_lookup.indp->get_mac(re->interface, re->default_gateway.value());
			}
		}

		if (po.value()->src_mac.has_value() == false)
			DOLOG(ll_warning, "router::operator: no src MAC address\n");
		else if (po.value()->dst_mac.has_value() == false)
			DOLOG(ll_warning, "router::operator: no dst MAC address\n");
		else if (re->interface->transmit_packet(po.value()->dst_mac.value(), po.value()->src_mac.value(), po.value()->ether_type, po.value()->data, po.value()->data_len) == false)
			DOLOG(ll_debug, "router::operator: cannot transmit_packet\n");

		delete po.value();
	}
}
