#pragma once

#include <map>
#include <optional>
#include <shared_mutex>
#include <stdint.h>
#include <thread>
#include <vector>

#include "log.h"
#include "stats.h"
#include "utils.h"


class arp;
class ndp;
class phys;

class router
{
private:
	class ip_router_entry {
	public:
		any_addr local_ip;

		any_addr network_address;

		union {
			uint8_t ipv4_netmask[4];

			int ipv6_prefix_length;
		} mask;

		int priority { -1 };

		phys *interface;

		union {
			arp *iarp;
			ndp *indp;
		} mac_lookup;

		std::optional<any_addr> default_gateway;

		std::string to_str();
	};

	class ax25_router_entry {
	public:
		std::optional<phys *>   interface;
		std::optional<any_addr> via;

		std::string to_str();
	};

	std::shared_mutex            table_lock;
	std::vector<ip_router_entry> ip_table;
	std::map<any_addr, ax25_router_entry> ax25_table;

	phys                        *ax25_default_interface { nullptr };

	class queued_packet {
	public:
		std::optional<any_addr> dst_mac;
		std::optional<any_addr> src_mac;

		uint16_t ether_type { 0 };

		std::optional<any_addr> dst_ip;
		std::optional<any_addr> src_ip;

		uint8_t *data     { nullptr };
		size_t   data_len { 0       };

		queued_packet(const uint8_t *const data, const size_t data_len) {
			this->data     = duplicate(data, data_len);
			this->data_len = data_len;
		}

		~queued_packet() {
			delete [] data;
		}

		std::string to_str() {
			std::string dst_mac_str = dst_mac.has_value() ? dst_mac.value().to_str() : "";
			std::string src_mac_str = src_mac.has_value() ? src_mac.value().to_str() : "";

			if (ether_type == 0x08FF)
				return src_mac_str + " -> " + dst_mac_str;

			return src_ip.value().to_str() + " (" + src_mac_str + ") -> " + dst_ip.value().to_str() + " (" + dst_mac_str + ")";
		}
	};

	fifo<queued_packet *>  *pkts { nullptr };

	std::vector<std::thread *> router_ths;

	std::atomic_bool stop_flag { false };

	ip_router_entry *find_route(const std::optional<any_addr> & mac, const any_addr & ip);

	std::optional<any_addr> resolve_mac_by_addr(ip_router_entry *const re, const any_addr & addr);

public:
	router(stats *const s, const int n_threads);
	virtual ~router();

	void stop();

	void set_default_ax25_interface(phys *const ax25_default_interface) { this->ax25_default_interface = ax25_default_interface; }

	void add_ax25_route(const any_addr & callsign, std::optional<phys *> interface, std::optional<any_addr> via);
	void add_router_ipv4(const any_addr & local_ip, const any_addr & network, const uint8_t netmask[4], const std::optional<any_addr> & gateway, const int priority, phys *const interface, arp *const iarp);
	void add_router_ipv6(const any_addr & local_ip, const any_addr & network, const int cidr, const int priority, phys *const interface, ndp *const indp);

	bool route_packet(const std::optional<any_addr> & override_dst_mac, const uint16_t ether_type, const any_addr & dst_ip, const std::optional<any_addr> & src_mac, const any_addr & src_ip, const uint8_t *const payload, const size_t pl_size);

	void dump();

	void operator()();
};
