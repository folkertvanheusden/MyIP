#include <assert.h>
#include <chrono>

#include "log.h"
#include "mac_resolver.h"
#include "time.h"


using namespace std::chrono_literals;

constexpr size_t pkts_max_size { 256 };

mac_resolver::mac_resolver(stats *const s, router *const r) :
	address_cache(s),
	network_layer(s, "mac-resolver", r)
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

std::optional<any_addr> mac_resolver::get_mac(phys *const interface, const any_addr & ip)
{
	assert(ip.get_family() == any_addr::ipv4);

	auto special_ip_addresses_mac = check_special_ip_addresses(ip);
	if (special_ip_addresses_mac.has_value())
		return special_ip_addresses_mac;

	auto cache_result = query_cache(ip);

	if (cache_result.first == interface) {
		any_addr rc = *cache_result.second;

		delete cache_result.second;

		return rc;
	}

	if (!send_request(ip))
		return { };

	DOLOG(ll_debug, "mac_resolver::get_mac waiting for %s\n", ip.to_str().c_str());

	uint64_t start_ts = get_ms();

	std::unique_lock<std::mutex> lck(work_lock);

	work.insert({ ip, { } });

	bool repeated = false;

	while(!stop_flag && get_ms() - start_ts < 1000) {
		auto it = work.find(ip);

		if (it == work.end()) {  // should not happen
			DOLOG(ll_error, "mac_resolver: nothing queued for %s\n", ip.to_str().c_str());

			return { };
		}

		if (it->second.has_value()) {
			auto result = it->second.value().mac;

			work.erase(it);

			if (result.has_value()) {
				DOLOG(ll_debug, "mac_resolver: resolved %s in %dms\n", ip.to_str().c_str(), get_ms() - start_ts);

				update_cache(result.value(), ip, interface);
			}
			else {
				DOLOG(ll_debug, "mac_resolver: no MAC found for %s\n", ip.to_str().c_str());
			}

			return result;
		}

		if (repeated == false && get_ms() - start_ts >= 500) {
			repeated = true;

			send_request(ip);
		}

		work_cv.wait_for(lck, 100ms);
	}

	DOLOG(ll_debug, "mac_resolver: resolve for %s timeout\n", ip.to_str().c_str());

	return { };
}
