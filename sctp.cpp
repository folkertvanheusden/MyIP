// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <chrono>

#include "buffer_in.h"
#include "ipv4.h"
#include "icmp.h"
#include "sctp.h"
#include "sctp_crc32c.h"
#include "utils.h"

// This code uses the 'buffer_in' object: it is a test for how well it is usable when
// implementing something like a protocol stack.
// Methods can be quite large as they're written *while* reading the RFC.

// TODO:
// - session cleaner

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

buffer_out sctp::init(sctp_session *const session, buffer_in & chunk_payload)
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

	buffer_out out;

	out.add_net_byte(2);  // INIT ACK
	out.add_net_byte(0);  // flags
  	size_t length_offset = out.add_net_short(0, -1);  // place holder for length
	out.add_net_long(session->my_verification_tag);
	out.add_net_long(sizeof session->buffer);  // a_rwnd
	out.add_net_short(1);  // number of outbound streams
	out.add_net_short(1);  // number of inbound streams
	out.add_net_long(session->my_verification_tag);  // initial TSN (transmission sequence number)

	// add state cookie (parameter)
	out.add_net_short(7);  // state cookie
	out.add_net_short(4);  // length of this parameter
	// TODO: when POC works, replace current sctp_session thing by proper
	// cookie-mechanism (see https://datatracker.ietf.org/doc/html/rfc4960#section-5.1.3 )

	// update chunk meta data (length field)
	out.add_net_short(out.get_size(), length_offset);

	out.add_padding(4);

	return out;
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
			std::shared_lock<std::shared_mutex> slck(sessions_lock, std::defer_lock_t());
			std::unique_lock<std::shared_mutex> ulck(sessions_lock, std::defer_lock_t());

			buffer_out reply;

			buffer_in b(p, size);

			uint16_t source_port      = b.get_net_short();
			uint16_t destination_port = b.get_net_short();
			uint32_t verification_tag = b.get_net_long();
			uint32_t checksum         = b.get_net_long();

			sctp_session *session           = new sctp_session(pkt->get_src_addr());
			session->their_verification_tag = verification_tag;
			session->their_port_number      = source_port;
			session->my_port_number         = destination_port;

			slck.lock();  // lock shared

			uint64_t hash = session->get_id_hash();
			auto it       = sessions.find(hash);
			bool found    = it != sessions.end();

			if (found) {
				delete session;

				session = it->second;

				session->update_last_packet();
			}
			else {
				slck.unlock();  // unlock shared
				
				ulck.lock();  // lock unique

				// TODO: check that it is not set to 0
				get_random(reinterpret_cast<uint8_t *>(&session->my_verification_tag), sizeof session->my_verification_tag);

				sessions.insert({ hash, session });

				ulck.unlock(); // unlock unique

				// <-- here an other thread can terminate/delete this thread
				//     that's perfectly fine; see the find below

				slck.lock();  // lock shared

				it = sessions.find(session->get_id_hash());
				if (it == sessions.end()) {
					delete session;

					continue;
				}
			}

			// session is now created/allocated
			// sessions is now shared-locked

			reply.add_net_short(session->my_port_number);
			reply.add_net_short(session->their_port_number);
			reply.add_net_long (session->my_verification_tag);
			size_t crc_offset = reply.add_net_long(0, -1);  // place-holder for crc

			DOLOG(dl, "SCTP: source port %d destination port %d, size: %d\n", source_port, destination_port, size);

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

					reply.add_buffer_out(init(session, chunk));
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

			// calculate & set crc in 'reply'
			uint32_t crc32c = generate_crc32c(reply.get_content(), reply.get_size());
			reply.add_net_long(crc32c, crc_offset);

			// transmit 'reply' (0x84 is SCTP protocol number)
			if (idev->transmit_packet(pkt->get_src_addr(), pkt->get_dst_addr(), 0x84, reply.get_content(), reply.get_size(), nullptr) == false)
				DOLOG(info, "SCTP: failed to transmit reply packet\n");
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
