#include <assert.h>
#include <map>
#include <set>
#include <thread>

#include "any_addr.h"
#include "arp.h"
#include "ndp.h"
#include "net.h"
#include "phys.h"
#include "router.h"
#include "str.h"


constexpr size_t pkts_max_size { 256 };

std::string router::router_entry::to_str()
{
	std::string mask_str = "-";

	if (network_address.get_family() == any_addr::ipv4)
		mask_str = myformat("%d.%d.%d.%d", mask.ipv4_netmask[0], mask.ipv4_netmask[1], mask.ipv4_netmask[2], mask.ipv4_netmask[3]);
	else if (network_address.get_family() == any_addr::ipv6)
		mask_str = myformat("%d", mask.ipv6_prefix_length);

	return network_address.to_str() + "/" + mask_str + " -> " + (default_gateway.has_value() ? default_gateway.value().to_str() : "-") + " " + interface->to_str();
}

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
	stop();

	for(auto th : router_ths) {
		th->join();

		delete th;
	}

	delete pkts;
}

void router::stop()
{
	pkts->interrupt();
}

void router::add_router_ipv4(const any_addr & local_ip, const any_addr & network, const uint8_t netmask[4], const std::optional<any_addr> & gateway, const int priority, phys *const interface, arp *const iarp)
{
	assert(network.get_family() == any_addr::ipv4);

	router_entry re;

	re.local_ip             = local_ip;
	re.network_address      = network;
	re.mask.ipv4_netmask[0] = netmask[0];
	re.mask.ipv4_netmask[1] = netmask[1];
	re.mask.ipv4_netmask[2] = netmask[2];
	re.mask.ipv4_netmask[3] = netmask[3];
	re.interface            = interface;
	re.mac_lookup.iarp      = iarp;
	re.default_gateway      = gateway;
	re.priority             = priority;

	std::unique_lock<std::shared_mutex> lck(table_lock);

	bool found = false;
	for(auto & e: table) {
		if (re.network_address == e.network_address && memcmp(re.mask.ipv4_netmask, e.mask.ipv4_netmask, 4) == 0 && e.interface == interface) {
			DOLOG(ll_debug, "router::add_router_ipv4: updated %s/%d.%d.%d.%d to gateway %s via %s\n", re.network_address.to_str().c_str(),
					netmask[0], netmask[1], netmask[2], netmask[3], gateway.has_value() ? gateway.value().to_str().c_str() : "-",
					interface->to_str().c_str());

			e.mac_lookup.iarp = iarp;
			e.default_gateway = gateway;

			found             = true;
			break;
		}
	}

	if (!found) {
		DOLOG(ll_debug, "router::add_router_ipv4: added route %s/%d.%d.%d.%d via gateway %s via %s\n", re.network_address.to_str().c_str(),
				netmask[0], netmask[1], netmask[2], netmask[3], gateway.has_value() ? gateway.value().to_str().c_str() : "-",
				interface->to_str().c_str());

		table.push_back(re);
	}
}

void router::add_router_ipv6(const any_addr & local_ip, const any_addr & network, const int cidr, const int priority, phys *const interface, ndp *const indp)
{
	assert(network.get_family() == any_addr::ipv6);

	router_entry re;

	re.local_ip                = local_ip;
	re.network_address         = network;
	re.mask.ipv6_prefix_length = cidr;
	re.interface               = interface;
	re.mac_lookup.indp         = indp;
	re.priority                = priority;

	std::unique_lock<std::shared_mutex> lck(table_lock);

	bool found = false;
	for(auto & e : table) {
		if (e.network_address == re.network_address && e.mask.ipv6_prefix_length == re.mask.ipv6_prefix_length) {
			found = true;
			break;
		}
	}

	if (!found) {
		DOLOG(ll_debug, "router::add_router_ipv6: added route %s/%d via interface %s\n", re.network_address.to_str().c_str(),
				cidr, interface->to_str().c_str());

		table.push_back(re);
	}
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

void router::dump()
{
	std::set<phys *> interfaces;

	DOLOG(ll_debug, "routing table:\n");

	std::shared_lock<std::shared_mutex> lck(table_lock);

	for(auto & entry : table) {
		DOLOG(ll_debug, ("| " + entry.to_str() + "\n").c_str());

		interfaces.insert(entry.interface);
	}

	DOLOG(ll_debug, "arp tables:\n");

	for(auto & i : interfaces)
		DOLOG(ll_debug, ("| " + i->to_str() + "\n").c_str());

	DOLOG(ll_debug, "-----\n");
}

router::router_entry *router::find_route(const std::optional<any_addr> & mac, const any_addr & ip)
{
	router_entry *re = nullptr;

	for(auto & entry : table) {
		if (entry.network_address.get_family() != ip.get_family())
			continue;

		if (mac.has_value() == true && entry.interface->get_phys_type() != mac.value().get_family())
			continue;

		if (entry.network_address.get_family() == any_addr::ipv4) {
			if (check_subnet(ip, entry.network_address, entry.mask.ipv4_netmask)) {
				if (re == nullptr || entry.priority > re->priority)
					re = &entry; // route through this
			}
		}
		else if (entry.network_address.get_family() == any_addr::ipv6) {
			if (check_subnet(ip, entry.network_address, entry.mask.ipv6_prefix_length)) {
				if (re == nullptr || entry.priority > re->priority)
					re = &entry;
			}
		}
		else {
			DOLOG(ll_warning, "router::find_route: unknown address family in queued packet (%d)\n", ip.get_family());
		}
	}

	return re;
}

std::optional<any_addr> router::resolve_mac_by_addr(router_entry *const re, const any_addr & addr)
{
	if (re->network_address.get_family() == any_addr::ipv4)
		return re->mac_lookup.iarp->get_mac(re->interface, addr);

	if (re->network_address.get_family() == any_addr::ipv6)
		return re->mac_lookup.indp->get_mac(re->interface, addr);

	return { };
}

void router::operator()()
{
	set_thread_name("myip-phys_router");

	for(;;) {
		auto po = pkts->get();
		if (!po.has_value())
			break;

		std::shared_lock<std::shared_mutex> lck(table_lock);

		// also required: for MAC lookups
		router_entry *re_src = find_route(po.value()->src_mac, po.value()->src_ip);

		if (!re_src) {
			DOLOG(ll_debug, "router::operator: no route for source (%s)\n", po.value()->to_str().c_str());
			continue;
		}

		DOLOG(ll_debug, "router::operator: selected source routing entry: %s\n", re_src->to_str().c_str());

		router_entry *re_dst = find_route(po.value()->dst_mac, po.value()->dst_ip);

		if (!re_dst) {
			DOLOG(ll_debug, "router::operator: no route for destination (%s)\n", po.value()->to_str().c_str());
			continue;
		}

		DOLOG(ll_debug, "router::operator: selected destination routing entry: %s\n", re_dst->to_str().c_str());

		// when routing to an other physical address family, use for source-mac the local
		// destination-interface mac as we're a router
		if (re_src != re_dst) {
			DOLOG(ll_info, "router::operator: src-route different from dst-route\n");

			re_src = re_dst;

			po.value()->src_mac = resolve_mac_by_addr(re_dst, re_dst->local_ip);
		}

		if (po.value()->src_mac.has_value() == false) {
			DOLOG(ll_debug, "router::operator: src-mac not known yet\n");

			// must always succeed, see main where a static rarp is setup
			po.value()->src_mac = resolve_mac_by_addr(re_src, po.value()->src_ip);

			if (po.value()->src_mac.has_value() == false)
				DOLOG(ll_info, "router::operator: cannot determine mac for source (%s)\n", po.value()->src_mac.value().to_str().c_str());
		}

		if (po.value()->dst_mac.has_value() == false) {
			DOLOG(ll_debug, "router::operator: dst-mac not known yet\n");

			po.value()->dst_mac = resolve_mac_by_addr(re_dst, po.value()->dst_ip);

			// not found? try the default gateway
			if (po.value()->dst_mac.has_value() == false && re_dst->default_gateway.has_value()) {
				DOLOG(ll_debug, "router::operator: MAC for %s not found, resolving default gateway (%s)\n", po.value()->dst_ip.to_str().c_str(), re_dst->default_gateway.value().to_str().c_str());

				po.value()->dst_mac = resolve_mac_by_addr(re_dst, re_dst->default_gateway.value());

				if (po.value()->dst_mac.has_value())
					DOLOG(ll_debug, "router::operator: default gateway (%s) can be reached via %s\n", po.value()->dst_ip.to_str().c_str(), re_dst->default_gateway.value().to_str().c_str(), po.value()->dst_mac.value().to_str().c_str());
			}
		}

		bool ok = true;

		if (po.value()->src_mac.has_value() == false) {
			ok = false;
			DOLOG(ll_warning, "router::operator: no src MAC address (%s)\n", po.value()->to_str().c_str());
		}

		if (po.value()->dst_mac.has_value() == false) {
			ok = false;
			DOLOG(ll_warning, "router::operator: no dst MAC address (%s)\n", po.value()->to_str().c_str());
		}

		if (ok) {
			DOLOG(ll_debug, "router::operator: transmit packet from %s (%s) to %s (%s) via %s\n",
					po.value()->src_ip.to_str().c_str(), po.value()->src_mac.value().to_str().c_str(),
					po.value()->dst_ip.to_str().c_str(), po.value()->dst_mac.value().to_str().c_str(),
					re_dst->interface->to_str().c_str());

			if (re_dst->interface->transmit_packet(po.value()->dst_mac.value(), po.value()->src_mac.value(), po.value()->ether_type, po.value()->data, po.value()->data_len) == false) {
				DOLOG(ll_debug, "router::operator: cannot transmit_packet (%s)\n", po.value()->to_str().c_str());
			}
		}
		else {
			dump();
		}

		delete po.value();
	}
}
