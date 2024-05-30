#pragma once
#include <condition_variable>
#include <map>
#include <mutex>
#include <optional>

#include "address_cache.h"
#include "any_addr.h"
#include "fifo.h"
#include "network_layer.h"
#include "router.h"
#include "stats.h"


class mac_resolver : public address_cache, public network_layer
{
public:
	class mac_resolver_result {
	public:
		std::optional<any_addr> mac;
	};

protected:
	std::map<any_addr, std::optional<mac_resolver_result> > work;
	mutable std::mutex work_lock;
	std::condition_variable work_cv;

	bool                  stop_flag { false   }; 

	fifo<fifo_element_t> *pkts      { nullptr };

	virtual bool send_request(const any_addr & ip, const any_addr::addr_family af) = 0;

	virtual std::optional<any_addr> check_special_ip_addresses(const any_addr & ip, const any_addr::addr_family family) = 0;

	void dump_work() const;

public:
	mac_resolver(stats *const s, router *const r);
	virtual ~mac_resolver();

	std::optional<std::pair<phys*, any_addr> > get_mac(phys *const interface, const any_addr & ip);

	std::map<any_addr, std::optional<mac_resolver::mac_resolver_result> > dump_state() const;

	any_addr get_addr() const override;

	void queue_incoming_packet(phys *const interface, packet *p) override;

	bool transmit_packet(const std::optional<any_addr> & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;

	int get_max_packet_size() const override;

	virtual void operator()() override = 0;
};
