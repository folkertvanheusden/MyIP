#include <assert.h>
#include <map>
#include <set>
#include <thread>

#include "address_cache.h"
#include "any_addr.h"
#include "arp.h"
#include "ndp.h"
#include "net.h"
#include "phys.h"
#include "router.h"
#include "str.h"


constexpr size_t pkts_max_size { 256 };

std::string router::ip_router_entry::to_str()
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

	ip_router_entry re;

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
	for(auto & e: ip_table) {
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

		ip_table.push_back(re);
	}
}

void router::add_router_ipv6(const any_addr & local_ip, const any_addr & network, const int cidr, const int priority, phys *const interface, ndp *const indp)
{
	assert(network.get_family() == any_addr::ipv6);

	ip_router_entry re;

	re.local_ip                = local_ip;
	re.network_address         = network;
	re.mask.ipv6_prefix_length = cidr;
	re.interface               = interface;
	re.mac_lookup.indp         = indp;
	re.priority                = priority;

	std::unique_lock<std::shared_mutex> lck(table_lock);

	bool found = false;
	for(auto & e : ip_table) {
		if (e.network_address == re.network_address && e.mask.ipv6_prefix_length == re.mask.ipv6_prefix_length) {
			found = true;
			break;
		}
	}

	if (!found) {
		DOLOG(ll_debug, "router::add_router_ipv6: added route %s/%d via interface %s\n", re.network_address.to_str().c_str(),
				cidr, interface->to_str().c_str());

		ip_table.push_back(re);
	}
}

bool router::route_packet(const std::optional<any_addr> & override_dst_mac, const uint16_t ether_type, const any_addr & dst_ip, const std::optional<any_addr> & src_mac, const any_addr & src_ip, const uint8_t *const payload, const size_t pl_size)
{
	queued_packet *qp = new queued_packet(payload, pl_size);

	qp->ether_type = ether_type;

	assert(override_dst_mac.has_value() == false || override_dst_mac.value().get_family() == any_addr::mac || override_dst_mac.value().get_family() == any_addr::ax25);
	qp->dst_mac    = override_dst_mac;

	assert(src_mac.has_value() == false || src_mac.value().get_family() == any_addr::mac || src_mac.value().get_family() == any_addr::ax25);
	qp->src_mac    = src_mac;

	if (ether_type != 0x08FF) {  // unofficial AX.25 ethertype
		assert(dst_ip.get_family() == any_addr::ipv4 || dst_ip.get_family() == any_addr::ipv6);
		qp->dst_ip     = dst_ip;

		assert(src_ip.get_family() == any_addr::ipv4 || src_ip.get_family() == any_addr::ipv6);
		qp->src_ip     = src_ip;
	}

	return pkts->try_put(qp);
}

void router::dump()
{
	std::set<phys *> interfaces;

	DOLOG(ll_debug, "routing tables (IP):\n");

	std::shared_lock<std::shared_mutex> lck(table_lock);

	for(auto & entry : ip_table) {
		DOLOG(ll_debug, ("| " + entry.to_str() + "\n").c_str());

		interfaces.insert(entry.interface);
	}
	if (ip_table.empty())
		DOLOG(ll_debug, " --- \n");

	if (ax25_table.empty() == false) {
		DOLOG(ll_debug, "routing tables (AX.25):\n");

		for(auto & entry : ax25_table) {
			if (entry.second.interface.has_value())
				DOLOG(ll_debug, ("| " + entry.first.to_str() + " -> " + entry.second.interface.value()->to_str() + "\n").c_str());

			if (entry.second.via.has_value())
				DOLOG(ll_debug, ("| " + entry.first.to_str() + " -> " + entry.second.via.value().to_str() + "\n").c_str());
		}
	}

	DOLOG(ll_debug, "arp tables:\n");
	address_cache::dump_cache();

	DOLOG(ll_debug, "-----\n");
}

router::ip_router_entry *router::find_route(const std::optional<any_addr> & mac, const any_addr & ip)
{
	ip_router_entry *re = nullptr;

	for(auto & entry : ip_table) {
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

std::optional<std::pair<phys *, any_addr> > router::resolve_mac_by_addr(ip_router_entry *const re, const any_addr & addr)
{
	if (re->network_address.get_family() == any_addr::ipv4)
		return re->mac_lookup.iarp->get_mac(re->interface, addr);

	if (re->network_address.get_family() == any_addr::ipv6)
		return re->mac_lookup.indp->get_mac(re->interface, addr);

	return { };
}

std::optional<phys *> router::find_interface_by_mac(ip_router_entry *const re, const any_addr & mac)
{
	return re->mac_lookup.iarp->get_phys_by_mac(mac);
}

std::string addr_string_if_has_value(const std::optional<any_addr> & a)
{
	if (a.has_value())
		return a.value().to_str();

	return "-";
}

void router::operator()()
{
	set_thread_name("myip-phys_router");

	for(;;) {
		auto po = pkts->get();
		if (!po.has_value())
			break;

		DOLOG(ll_debug, "router::operator: routing %s (%s) to %s (%s)\n",
				addr_string_if_has_value(po.value()->src_ip).c_str(), addr_string_if_has_value(po.value()->src_mac).c_str(),
                                addr_string_if_has_value(po.value()->dst_ip).c_str(), addr_string_if_has_value(po.value()->dst_mac).c_str());

		bool     ok        = false;

		phys    *interface = nullptr;
		any_addr dst_mac;
		any_addr src_mac;

		do {
			std::shared_lock<std::shared_mutex> lck(table_lock);

			auto dst_route = find_route(po.value()->dst_mac, po.value()->dst_ip.value());
			if (dst_route)
				DOLOG(ll_debug, "dst_route known: %s\n", dst_route->to_str().c_str());

			auto src_route = find_route(po.value()->src_mac, po.value()->src_ip.value());
			if (src_route)
				DOLOG(ll_debug, "src_route known: %s\n", src_route->to_str().c_str());

			if (dst_route && src_route) {
				DOLOG(ll_debug, "src_route and dst_route known\n");

				// destination ip known
				if (po.value()->dst_mac.has_value())
					// destination mac known
					dst_mac = po.value()->dst_mac.value();
				else {
					// target mac not known
					// find mac of target
					auto local_adapter_target_mac_dst = resolve_mac_by_addr(dst_route, po.value()->dst_ip.value());
					if (local_adapter_target_mac_dst.has_value()) {  // route via interface that can reach this ip-address
						dst_mac   = local_adapter_target_mac_dst.value().second;
						interface = local_adapter_target_mac_dst.value().first;
					}
					else if (src_route->default_gateway.has_value()) {  // route via default gateway
						auto local_adapter_target_mac_gw = resolve_mac_by_addr(dst_route, src_route->default_gateway.value());

						// route via gateway
						if (local_adapter_target_mac_gw.has_value()) {
							dst_mac   = local_adapter_target_mac_dst.value().second;
							interface = local_adapter_target_mac_dst.value().first;
						}
						else {
							DOLOG(ll_warning, "cannot find router mac/interface\n");
							break;
						}
					}
					else {
						DOLOG(ll_warning, "cannot find dst_mac/interface for dst_ip\n");
						break;
					}

					if (interface == nullptr) {
						DOLOG(ll_warning, "cannot find dst interface\n");
						break;
					}
				}

				if (dst_route->interface != src_route->interface) {
					DOLOG(ll_debug, "dst interface different from src interface\n");

					src_mac   = dst_route->interface->get_local_mac();
					interface = dst_route->interface;

					ok = true;
					break;
				}
				else {
					DOLOG(ll_debug, "dst interface equal to src interface\n");

					src_mac   = src_route->interface->get_local_mac();
					interface = dst_route->interface;

					ok = true;
					break;
				}

				DOLOG(ll_warning, "this should not be reached\n");
			}

			DOLOG(ll_warning, "source or destination route not known\n");
		}
		while(0);

		if (ok) {
			DOLOG(ll_debug, "router::operator: transmit packet from %s to %s via %s\n",
					src_mac.to_str().c_str(),
					dst_mac.to_str().c_str(),
					interface->to_str().c_str());

			if (interface->transmit_packet(dst_mac, src_mac, po.value()->ether_type, po.value()->data, po.value()->data_len) == false) {
				DOLOG(ll_debug, "router::operator: cannot transmit_packet (%s) via %s\n", po.value()->to_str().c_str(), interface->to_str().c_str());
			}
		}
		else {
			dump();
		}

		delete po.value();
	}
}

void router::add_ax25_route(const any_addr & callsign, std::optional<phys *> interface, std::optional<any_addr> via)
{
	ax25_router_entry re;
	re.interface = interface;
	re.via       = via;

	ax25_table.insert_or_assign(callsign, std::move(re));
}
