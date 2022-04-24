// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <time.h>
#include <openssl/hmac.h>

#include "buffer_in.h"
#include "ipv4.h"
#include "icmp.h"
#include "sctp.h"
#include "sctp_crc32c.h"
#include "utils.h"

// This code uses the 'buffer_in' object: it is a test for how well it is usable when
// implementing something like a protocol stack.
// Methods can be quite large as they're written *while* reading the RFC (4960).

// TODO:
// - session cleaner

// debug level
constexpr log_level_t dl = info;

sctp::sctp(stats *const s, icmp *const icmp_) : ip_protocol(s, "sctp"), icmp_(icmp_)
{
	sctp_msgs        = s->register_stat("sctp_msgs");
	sctp_failed_msgs = s->register_stat("sctp_failed_msgs");

	get_random(state_cookie_key, sizeof state_cookie_key);
	state_cookie_key_timestamp = time(nullptr);

	th = new std::thread(std::ref(*this));
}

sctp::~sctp()
{
	stop_flag = true;

	th->join();
	delete th;
}

std::pair<uint16_t, buffer_in> sctp::get_parameter(buffer_in & chunk_payload)
{
	uint16_t type      = chunk_payload.get_net_short();
	uint8_t  type_type = type & 0x3fff;
	uint8_t  type_unh  = type >> 14;  // what to do when it can not be processed

	uint16_t len       = chunk_payload.get_net_short();

	// len is including the header (excluding the padding)
	if (len < 4)
		throw std::out_of_range("sctp::get_parameter");

	DOLOG(dl, "SCTP parameter of type %d/%d and length %d\n", type_unh, type_type, len);

	buffer_in   value     = chunk_payload.get_segment(len - 4);

	uint8_t  padding   = len & 3;
	if (padding) {
		padding = 4 - padding;

		DOLOG(dl, "SCTP parameter padding: %d bytes\n", padding);

		chunk_payload.seek(padding);
	}

	return { type, value };
}

buffer_out sctp::generate_state_cookie(const any_addr & their_addr, const int their_port, const int local_port)
{
	buffer_out sc;

	sc.add_net_byte(their_addr.get_len());
	sc.add_any_addr(their_addr);

	sc.add_net_short(their_port);

	sc.add_net_short(local_port);

	sc.add_net_long(time(nullptr));

	uint8_t hash[64] { 0 };
	HMAC(EVP_sha512(), state_cookie_key, sizeof state_cookie_key, sc.get_content(), sc.get_size(), hash, nullptr);

	sc.add_buffer(hash, sizeof hash);

	return sc;
}

void sctp::init(buffer_in & chunk_payload, const uint32_t my_verification_tag, const uint32_t buffer_size, const any_addr & their_addr, const int their_port, const int local_port, buffer_out *const out, uint32_t *const initiate_tag)
{
	        *initiate_tag = chunk_payload.get_net_long();
	uint32_t a_rwnd       = chunk_payload.get_net_long();

	uint16_t n_outbound_streams = chunk_payload.get_net_short();
	uint16_t n_inbound_streams  = chunk_payload.get_net_short();

	uint32_t initial_tsn  = chunk_payload.get_net_long();

	while(chunk_payload.end_reached() == false) {
		auto parameter = get_parameter(chunk_payload);

		DOLOG(dl, "SCTP: INIT parameter block of type %d and size %d\n", parameter.first, parameter.second.get_n_bytes_left());
	}

	out->add_net_byte(2);  // INIT ACK
	out->add_net_byte(0);  // flags
  	size_t length_offset = out->add_net_short(0, -1);  // place holder for length
	out->add_net_long(my_verification_tag);
	out->add_net_long(buffer_size);  // a_rwnd
	out->add_net_short(1);  // number of outbound streams
	out->add_net_short(1);  // number of inbound streams
	out->add_net_long(my_verification_tag);  // initial TSN (transmission sequence number)

	// add state cookie (parameter)
	out->add_net_short(7);  // state cookie
	auto state_cookie = generate_state_cookie(their_addr, their_port, local_port);
	out->add_net_short(4 + state_cookie.get_size());  // length of this parameter
	out->add_buffer_out(state_cookie);

	// update chunk meta data (length field)
	out->add_net_short(out->get_size(), length_offset);

	out->add_padding(4);
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

		// TODO move this into a thread
		try {
			const any_addr their_addr = pkt->get_src_addr();

			buffer_in b(p, size);

			uint16_t source_port            = b.get_net_short();  // their port
			uint16_t destination_port       = b.get_net_short();  // local port
			uint32_t their_verification_tag = b.get_net_long();
			uint32_t checksum               = b.get_net_long();

			DOLOG(dl, "SCTP: source port %d destination port %d, size: %d, verification tag: %08x\n", source_port, destination_port, size, their_verification_tag);

			uint32_t my_verification_tag = 0;

			// verification tag may not be 0
			do {
				get_random(reinterpret_cast<uint8_t *>(&my_verification_tag), sizeof my_verification_tag);
			} while(my_verification_tag == 0);

			bool send_reply = true;

			buffer_out reply;

			reply.add_net_short(destination_port);
			reply.add_net_short(source_port);
			size_t their_verification_tag_offset = reply.add_net_long(their_verification_tag, -1);  // will be 0 in INIT, will be replaced by initial tag
			size_t crc_offset = reply.add_net_long(0, -1);  // place-holder for crc

			while(b.end_reached() == false) {
				uint8_t  type      = b.get_net_byte();
				uint8_t  flags     = b.get_net_byte();
				uint16_t len       = b.get_net_short();

				uint8_t  type_type = type & 63;
				uint8_t  type_unh  = type >> 6;  // what to do when it can not be processed

				if (len < 4) {
					DOLOG(dl, "SCTP: chunk too short\n");
					break;
				}

				buffer_in chunk    = b.get_segment(len - 4);

				DOLOG(dl, "SCTP: type %d flags %d length %d\n", type, flags, len);

				if (type == 1) {  // INIT
					DOLOG(dl, "SCTP: INIT chunk of length %d\n", chunk.get_n_bytes_left());
					
					uint32_t initial_verification_tag = 0;

					buffer_out temp;
					init(chunk, my_verification_tag, 4096 /* TODO */, their_addr, source_port, destination_port, &temp, &initial_verification_tag);

					reply.add_net_long(initial_verification_tag, their_verification_tag_offset);

					reply.add_buffer_out(temp);
				}
				else {
					DOLOG(dl, "SCTP: %d is an unknown chunk type\n", type);

					send_reply = false;
				}

				uint8_t  padding   = len & 3;
				if (padding) {
					padding = 4 - padding;

					DOLOG(dl, "SCTP chunk padding: %d bytes\n", padding);

					b.seek(padding);
				}
			}

			if (send_reply) {
				// calculate & set crc in 'reply'
				uint32_t crc32c = generate_crc32c(reply.get_content(), reply.get_size());
				reply.add_net_long(crc32c, crc_offset);

				// transmit 'reply' (0x84 is SCTP protocol number)
				if (idev->transmit_packet(their_addr, pkt->get_dst_addr(), 0x84, reply.get_content(), reply.get_size(), nullptr) == false)
					DOLOG(info, "SCTP: failed to transmit reply packet\n");
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
