#include "router.h"


router::router()
{
}

router::~router()
{
}

bool router::route_packet(const std::optional<any_addr> & override_dst_mac, const uint16_t ether_type, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t *const payload, const size_t pl_size)
{
	queued_packet *qp = new queued_packet(payload, pl_size);

	qp->ether_type = ether_type;

	qp->dst_mac = override_dst_mac;

	qp->dst_ip  = dst_ip;
	qp->src_ip  = src_ip;

	return pkts.try_put(qp);
}

void router::operator()()
{
	while(!terminate) {
		auto po = pkts.get(500);
		if (!po.has_value())
			continue;

		if (po.value()->dst_mac.has_value() == false) {
			// TODO arp
		}

		std::shared_lock<std::shared_mutex> lck(table_lock);

		for(auto & entry : table) {
			if (entry.network_address.get_len() != po.value()->src_ip.get_len())  // TODO: replace by check for type
				continue;

			if (entry.network_address.get_len() == 4) {  // TODO: ^
				bool match = true;

				for(int i=0; i<4; i++) {
					if ((po.value()->dst_ip[i] & entry.network_address[i]) != po.value()->dst_ip[i]) {
						match = false;
						break;
					}
				}

				if (match) {
					// TODO route through this interface:

					if (po.value()->src_mac.has_value() == false) {
						// TODO lookup src MAC address
						// TODO arp - should be statically stored -> depending on outgoing interface
					}
				}
			}
			else if (entry.network_address.get_len() == 6) {
			}
			else {
				DOLOG(ll_warning, "Unknown address type in queued packet\n");
			}
		}

	}
}
