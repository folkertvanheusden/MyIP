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
class phys;

class router
{
private:
	class router_entry {
	public:
		any_addr network_address;

		union {
			uint8_t ipv4_netmask[4];

			int ipv6_prefix_length;
		} mask;

		phys *interface;

		union {
			arp *iarp;
		} mac_lookup;

		std::optional<any_addr> default_gateway;
	};

	phys                     *default_interface { nullptr };

	std::shared_mutex         table_lock;
	std::vector<router_entry> table;

	class queued_packet {
	public:
		std::optional<any_addr> dst_mac;
		std::optional<any_addr> src_mac;

		uint16_t ether_type { 0 };

		any_addr dst_ip;
		any_addr src_ip;

		uint8_t *data     { nullptr };
		size_t   data_len { 0       };

		queued_packet(const uint8_t *const data, const size_t data_len) {
			this->data     = duplicate(data, data_len);
			this->data_len = data_len;
		}

		~queued_packet() {
			delete [] data;
		}
	};

	fifo<queued_packet *>  *pkts { nullptr };

	std::vector<std::thread *> router_ths;

	std::atomic_bool stop_flag { false };

public:
	router(stats *const s, const int n_threads);
	virtual ~router();

	void stop();

	void add_router_ipv4(const any_addr & network, const uint8_t netmask[4], const std::optional<any_addr> & gateway, phys *const interface, arp *const iarp);
	void add_router_ipv6(const any_addr & network, const int cidr, phys *const interface, arp *const iarp);

	void set_default_interface(phys *const default_interface) { this->default_interface = default_interface; }

	bool route_packet(const std::optional<any_addr> & override_dst_mac, const uint16_t ether_type, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t *const payload, const size_t pl_size);

	void operator()();
};
