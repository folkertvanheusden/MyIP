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
	stop_flag = true;

	delete pkts;
}

any_addr mac_resolver::get_addr() const
{
	assert(0);

	return any_addr();
}

std::map<any_addr, std::optional<mac_resolver::mac_resolver_result> > mac_resolver::dump_state() const
{
	std::unique_lock<std::mutex> lck(work_lock);

	DOLOG(ll_debug, "mac_resolver: returning %zu entries\n", work.size());

	return work;
}

void mac_resolver::queue_incoming_packet(phys *const interface, packet *p)
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

void mac_resolver::dump_work() const
{
	for(auto & e : work) {
		std::string mac = "?";

		if (e.second.has_value() && e.second.value().mac.has_value())
			mac = e.second.value().mac.value().to_str();

		DOLOG(ll_debug, "mac_resolver::dump: %s - %s\n", e.first.to_str().c_str(), mac.c_str());
	}

	DOLOG(ll_debug, "mac_resolver::dump: --- FIN ---\n");
}

std::optional<std::pair<phys*, any_addr> > mac_resolver::get_mac(phys *const interface, const any_addr & ip)
{
	DOLOG(ll_debug, "mac_resolver::get_mac: resolving %s\n", ip.to_str().c_str());

	auto phys_family = interface->get_phys_type();

	auto special_ip_addresses_mac = check_special_ip_addresses(ip, phys_family);
	if (special_ip_addresses_mac.has_value()) {
		DOLOG(ll_debug, "mac_resolver::get_mac: %s is special\n", ip.to_str().c_str());

		return { { interface, special_ip_addresses_mac.value() } };
	}

	auto cache_result = query_cache(ip);

	if (cache_result.first != nullptr) {
		any_addr rc = *cache_result.second;

		DOLOG(ll_debug, "mac_resolver::get_mac: %s is at %s\n", ip.to_str().c_str(), rc.to_str().c_str());

		delete cache_result.second;

		return { { cache_result.first, rc } };
	}

	if (!send_request(ip, phys_family)) {
		DOLOG(ll_debug, "mac_resolver::get_mac: failed to resolve %s: probleming sending request\n", ip.to_str().c_str());

		return { };
	}

	DOLOG(ll_debug, "mac_resolver::get_mac waiting for %s (on %s)\n", ip.to_str().c_str(), interface->to_str().c_str());

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

			return { { interface, result.value() } };
		}

		if (repeated == false && get_ms() - start_ts >= 500) {
			repeated = true;

			send_request(ip, phys_family);
		}

		work_cv.wait_for(lck, 100ms);
	}

	auto e_it = work.find(ip);
	if (e_it != work.end())
		work.erase(e_it);

	DOLOG(ll_debug, "mac_resolver: resolve %s timeout\n", ip.to_str().c_str());

	dump_work();

	return { };
}

std::optional<phys *> mac_resolver::get_phys_by_mac(const any_addr & mac)
{
	auto rc = query_mac_cache(mac);
	if (rc == nullptr)
		return { };

	return rc;
}
