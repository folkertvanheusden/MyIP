// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <chrono>

#include "buffer.h"
#include "ipv4.h"
#include "icmp.h"
#include "sctp.h"
#include "utils.h"

// This code uses the 'buffer' object: it is a test for how well it is usable when
// implementing something like a protocol stack.
// Methods can be quite large as they're written *while* reading the RFC.

// debug level
constexpr log_level_t dl = info;

sctp::sctp(stats *const s, icmp *const icmp_) : ip_protocol(s, "sctp"), icmp_(icmp_)
{
	sctp_msgs        = s->register_stat("sctp_msgs");
	sctp_failed_msgs = s->register_stat("sctp_failed_msgs");

	th = new std::thread(std::ref(*this));
}

sctp::~sctp()
{
	stop_flag = true;

	th->join();
	delete th;
}

std::pair<uint16_t, buffer> sctp::get_parameter(buffer & chunk_payload)
{
	uint16_t type      = chunk_payload.get_net_short();
	uint8_t  type_type = type & 0x3fff;
	uint8_t  type_unh  = type >> 14;  // what to do when it can not be processed

	uint16_t len       = chunk_payload.get_net_short();

	// len is including the header (excluding the padding)
	if (len < 4)
		throw std::out_of_range("sctp::get_parameter");

	DOLOG(dl, "SCTP parameter of type %d/%d and length %d\n", type_unh, type_type, len);

	buffer   value     = chunk_payload.get_segment(len - 4);

	uint8_t  padding   = len & 3;
	if (padding) {
		padding = 4 - padding;

		DOLOG(dl, "SCTP parameter padding: %d bytes\n", padding);

		chunk_payload.seek(padding);
	}

	return { type, value };
}

void sctp::init(buffer & chunk_payload)
{
	uint32_t initiate_tag = chunk_payload.get_net_long();
	uint32_t a_rwnd       = chunk_payload.get_net_long();

	uint16_t n_outbound_streams = chunk_payload.get_net_short();
	uint16_t n_inbound_streams  = chunk_payload.get_net_short();

	uint32_t initial_tsn  = chunk_payload.get_net_long();

	while(chunk_payload.end_reached() == false) {
		auto parameter = get_parameter(chunk_payload);

		DOLOG(dl, "SCTP: INIT parameter block of type %d and size %d\n", parameter.first, parameter.second.get_n_bytes_left());
	}
}

void sctp::operator()()
{
	set_thread_name("myip-sctp");

	while(!stop_flag) {
		auto po = pkts->get(500);
		if (!po.has_value())
			continue;

		const packet *pkt = po.value();

		const uint8_t *const p    = pkt->get_data();
		const int            size = pkt->get_size();

		if (size < 12) {
			DOLOG(dl, "SCTP: packet too small (%d bytes)\n", size);
			delete pkt;
			continue;
		}

		try {
			buffer b(p, size);

			uint16_t source_port      = b.get_net_short();
			uint16_t destination_port = b.get_net_short();
			uint32_t verification_tag = b.get_net_long();
			uint32_t checksum         = b.get_net_long();

			DOLOG(dl, "SCTP: source port %d destination port %d, size: %d\n", source_port, destination_port, size);

			while(b.end_reached() == false) {
				uint8_t  type      = b.get_byte();
				uint8_t  flags     = b.get_byte();
				uint16_t len       = b.get_net_short();

				uint8_t  type_type = type & 63;
				uint8_t  type_unh  = type >> 6;  // what to do when it can not be processed

				if (len < 4) {
					DOLOG(dl, "SCTP: chunk too short\n");
					break;
				}

				buffer chunk    = b.get_segment(len - 4);

				DOLOG(dl, "SCTP: type %d flags %d length %d\n", type, flags, len);

				if (type == 1) {  // INIT
					DOLOG(dl, "SCTP: INIT chunk of length %d\n", chunk.get_n_bytes_left());

					init(chunk);
				}
				else {
					DOLOG(dl, "SCTP: %d is an unknown chunk type\n", type);
				}

				uint8_t  padding   = len & 3;
				if (padding) {
					padding = 4 - padding;

					DOLOG(dl, "SCTP chunk padding: %d bytes\n", padding);

					b.seek(padding);
				}
			}
		}
		catch(std::out_of_range & e) {
			DOLOG(dl, "SCTP: truncated\n");
		}

		delete pkt;
	}
}

void sctp::add_handler(const int port, std::function<void(const any_addr &, int, const any_addr &, int, packet *, void *const pd)> h, void *pd)
{
}

void sctp::remove_handler(const int port)
{
}

bool sctp::transmit_packet(const any_addr & dst_ip, const int dst_port, const any_addr & src_ip, const int src_port, const uint8_t *payload, const size_t pl_size)
{
	return false;
}
