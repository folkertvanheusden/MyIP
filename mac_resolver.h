#pragma once
#include <condition_variable>
#include <map>
#include <mutex>
#include <optional>

#include "any_addr.h"
#include "fifo.h"
#include "network_layer.h"
#include "router.h"
#include "stats.h"


class mac_resolver : public network_layer
{
protected:
	class mac_resolver_result {
	public:
		std::optional<any_addr> mac;
	};

	std::map<any_addr, std::optional<mac_resolver_result> > work;
	std::mutex work_lock;
	std::condition_variable work_cv;

	fifo<fifo_element_t> *pkts { nullptr };

public:
	mac_resolver(stats *const s, router *const r);
	virtual ~mac_resolver();

	virtual std::optional<any_addr> get_mac(const any_addr & ip) = 0;

	void queue_incoming_packet(phys *const interface, const packet *p) override;

	bool transmit_packet(const std::optional<any_addr> & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;

	int get_max_packet_size() const override;

	virtual void operator()() override = 0;
};
