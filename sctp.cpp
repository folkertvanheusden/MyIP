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

std::pair<uint16_t, buffer_in> sctp::get_parameter(const uint64_t hash, buffer_in & chunk_payload)
{
	uint16_t type      = chunk_payload.get_net_short();
	uint8_t  type_type = type & 0x3fff;
	uint8_t  type_unh  = type >> 14;  // what to do when it can not be processed

	uint16_t len       = chunk_payload.get_net_short();

	// len is including the header (excluding the padding)
	if (len < 4)
		throw std::out_of_range("sctp::get_parameter");

	DOLOG(dl, "SCTP[%lx]: parameter of type %d/%d and length %d\n", hash, type_unh, type_type, len);

	buffer_in   value  = chunk_payload.get_segment(len - 4);

	uint8_t  padding   = len & 3;
	if (padding) {
		padding = 4 - padding;

		DOLOG(dl, "SCTP[%lx]: parameter padding: %d bytes\n", hash, padding);

		chunk_payload.seek(padding);
	}

	return { type, value };
}

buffer_out sctp::generate_state_cookie(const any_addr & their_addr, const int their_port, const int local_port, const uint32_t their_verification_tag, const uint32_t their_initial_tsn, const uint32_t my_initial_tsn)
{
	buffer_out sc;

	sc.add_net_long(their_verification_tag);

	sc.add_net_long(their_initial_tsn);
	sc.add_net_long(my_initial_tsn);

	sc.add_net_byte(their_addr.get_len());
	sc.add_any_addr(their_addr);

	sc.add_net_short(their_port);

	sc.add_net_short(local_port);

	sc.add_net_long(state_cookie_key_timestamp);

	uint8_t hash[28] { 0 };
	HMAC(EVP_sha3_224(), state_cookie_key, sizeof state_cookie_key, sc.get_content(), sc.get_size(), hash, nullptr);

	sc.add_buffer(hash, sizeof hash);

	return sc;
}

void sctp::chunk_init(const uint64_t hash, buffer_in & chunk_payload, const uint32_t my_verification_tag, const uint32_t buffer_size, const any_addr & their_addr, const int their_port, const int local_port, buffer_out *const out, uint32_t *const initiate_tag)
{
	        *initiate_tag = chunk_payload.get_net_long();
	uint32_t a_rwnd       = chunk_payload.get_net_long();

	uint16_t n_outbound_streams = chunk_payload.get_net_short();
	uint16_t n_inbound_streams  = chunk_payload.get_net_short();

	uint32_t their_initial_tsn  = chunk_payload.get_net_long();

	while(chunk_payload.end_reached() == false) {
		auto parameter = get_parameter(hash, chunk_payload);

		DOLOG(dl, "SCTP[%lx]: INIT parameter block of type %d and size %d\n", hash, parameter.first, parameter.second.get_n_bytes_left());
	}

	out->add_net_byte(2);  // INIT ACK
	out->add_net_byte(0);  // flags
  	size_t length_offset = out->add_net_short(0, -1);  // place holder for length
	out->add_net_long(my_verification_tag);
	out->add_net_long(buffer_size);  // a_rwnd
	out->add_net_short(1);  // number of outbound streams
	out->add_net_short(1);  // number of inbound streams
	uint32_t my_initial_tsn = my_verification_tag;
	out->add_net_long(my_initial_tsn);  // initial TSN (transmission sequence number)

	// add state cookie (parameter)
	out->add_net_short(7);  // state cookie
	auto state_cookie = generate_state_cookie(their_addr, their_port, local_port, *initiate_tag, their_initial_tsn, my_initial_tsn);
	out->add_net_short(4 + state_cookie.get_size());  // length of this parameter
	out->add_buffer_out(state_cookie);

	// update chunk meta data (length field)
	out->add_net_short(out->get_size(), length_offset);

	out->add_padding(4);
}

buffer_out sctp::chunk_gen_abort()
{
	buffer_out out;

	out.add_net_byte(6);  // SCTP ABORT
	out.add_net_byte(0);  // reserved
	out.add_net_short(4);  // length of this chunk

	return out;
}

buffer_out sctp::chunk_gen_cookie_ack()
{
	buffer_out out;

	out.add_net_byte(11);  // SCTP COOKIE ACK
	out.add_net_byte(0);  // reserved
	out.add_net_short(4);  // length of this chunk

	return out;
}

void sctp::chunk_cookie_echo(buffer_in & chunk_payload, const any_addr & their_addr, const int their_port, const int local_port, bool *const ok, uint32_t *const their_verification_tag, uint32_t *const their_initial_tsn, uint32_t *const my_initial_tsn)
{
	buffer_in  cookie_data  = chunk_payload.get_segment(chunk_payload.get_n_bytes_left());

	buffer_in  temp         = cookie_data;
	*their_verification_tag = temp.get_net_long();
	*their_initial_tsn      = temp.get_net_long();
	*my_initial_tsn         = temp.get_net_long();

	buffer_out state_cookie = generate_state_cookie(their_addr, their_port, local_port, *their_verification_tag, *their_initial_tsn, *my_initial_tsn);

	// sanity of *my_verification_tag is guaranteed by hmac which is verified here as well
	*ok = state_cookie.compare(cookie_data);
}

buffer_out sctp::chunk_heartbeat_request(buffer_in & chunk_payload)
{
	buffer_out out;

	out.add_net_byte(5);  // SCTP COOKIE ACK
	out.add_net_byte(0);  // reserved
	size_t length_offset = out.add_net_short(4, -1);  // length of this chunk

	out.add_buffer_in(chunk_payload);

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

		const packet        *pkt        = po.value();

		const any_addr       their_addr = pkt->get_src_addr();

		const uint8_t *const p          = pkt->get_data();
		const int            size       = pkt->get_size();

		if (size < 12) {
			DOLOG(dl, "SCTP(%s): packet too small (%d bytes)\n", their_addr.to_str().c_str(), size);
			delete pkt;
			continue;
		}

		// TODO move this into a thread
		try {
			buffer_in b(p, size);

			uint16_t source_port         = b.get_net_short();  // their port
			uint16_t destination_port    = b.get_net_short();  // local port
			uint32_t my_verification_tag = b.get_net_long();
			uint32_t checksum            = b.get_net_long();

			uint64_t hash                = sctp_session::get_hash(their_addr, source_port, destination_port);

			DOLOG(dl, "SCTP[%lx]: source addr %s, source port %d, destination port %d, size: %d, verification tag: %08x\n", hash, their_addr.to_str().c_str(), source_port, destination_port, size, my_verification_tag);

			bool send_reply = true;

			buffer_out reply;

			reply.add_net_short(destination_port);
			reply.add_net_short(source_port);
			size_t their_verification_tag_offset = reply.add_net_long(-1, -1);  // will be 0 in INIT, will be replaced by their verifiation/initial tag
			size_t crc_offset = reply.add_net_long(0, -1);  // place-holder for crc

			while(b.end_reached() == false) {
				uint8_t  type      = b.get_net_byte();
				uint8_t  flags     = b.get_net_byte();
				uint16_t len       = b.get_net_short();

				uint8_t  type_type = type & 63;
				uint8_t  type_unh  = type >> 6;  // what to do when it can not be processed

				if (len < 4) {
					DOLOG(dl, "SCTP[%lx]: chunk too short\n", hash);
					break;
				}

				buffer_in chunk    = b.get_segment(len - 4);

				DOLOG(dl, "SCTP[%lx]: type %d flags %d length %d\n", hash, type, flags, len);

				if (type == 1) {  // INIT
					DOLOG(dl, "SCTP[%lx]: INIT chunk of length %d\n", hash, chunk.get_n_bytes_left());
					
					uint32_t their_initial_verification_tag = 0;

					uint32_t my_new_verification_tag = 0;

					// verification tag may not be 0
					do {
						get_random(reinterpret_cast<uint8_t *>(&my_new_verification_tag), sizeof my_new_verification_tag);
					} while(my_new_verification_tag == 0);

					buffer_out temp;
					chunk_init(hash, chunk, my_new_verification_tag, 4096 /* TODO */, their_addr, source_port, destination_port, &temp, &their_initial_verification_tag);

					reply.add_net_long(their_initial_verification_tag, their_verification_tag_offset);

					reply.add_buffer_out(temp);
				}
				else if (type == 4) {  // HEARTBEAT (-request)
					DOLOG(dl, "SCTP[%lx]: heartbeat request received\n", hash);

					reply.add_buffer_out(chunk_heartbeat_request(chunk));
				}
				else if (type == 6) {  // ABORT
					DOLOG(dl, "SCTP[%lx]: abort request received\n", hash);

					std::unique_lock<std::shared_mutex> lck(sessions_lock);

					sessions.erase(hash);
				}
				else if (type == 10) {  // COOKIE ECHO
					bool     cookie_ok              = false;

					uint32_t their_verification_tag = 0;
					uint32_t their_initial_tsn      = 0;
					uint32_t my_initial_tsn         = 0;

					chunk_cookie_echo(chunk, their_addr, source_port, destination_port, &cookie_ok, &their_verification_tag, &their_initial_tsn, &my_initial_tsn);

					if (cookie_ok) {
						// register session
						{
							std::unique_lock<std::shared_mutex> lck(sessions_lock);

							if (sessions.find(hash) != sessions.end())
								DOLOG(dl, "SCTP[%lx]: session already on-going\n", hash);
							else {
								DOLOG(dl, "SCTP[%lx]: their initial tsn: %08x, my initial tsn: %08x\n", hash, their_initial_tsn, my_initial_tsn);

								sctp_session *session = new sctp_session(their_addr, source_port, destination_port, their_initial_tsn, my_initial_tsn);

								sessions.insert({ hash, session });
							}
						}

						// send ack
						reply.add_buffer_out(chunk_gen_cookie_ack());

						DOLOG(dl, "SCTP[%lx]: COOKIE ECHO ACK\n", hash);
					}
					else {
						// send deny
						reply.add_buffer_out(chunk_gen_abort());

						DOLOG(dl, "SCTP[%lx]: ABORT\n", hash);
					}

					reply.add_net_long(their_verification_tag, their_verification_tag_offset);
				}
				else {
					DOLOG(dl, "SCTP[%lx]: %d is an unknown chunk type\n", hash, type);

					send_reply = false;
				}

				uint8_t  padding   = len & 3;
				if (padding) {
					padding = 4 - padding;

					DOLOG(dl, "SCTP[%lx]: chunk padding: %d bytes\n", hash, padding);

					b.seek(padding);
				}
			}

			if (send_reply) {
				// calculate & set crc in 'reply'
				uint32_t crc32c = generate_crc32c(reply.get_content(), reply.get_size());
				reply.add_net_long(crc32c, crc_offset);

				// transmit 'reply' (0x84 is SCTP protocol number)
				if (idev->transmit_packet(their_addr, pkt->get_dst_addr(), 0x84, reply.get_content(), reply.get_size(), nullptr) == false)
					DOLOG(info, "SCTP[%lx]: failed to transmit reply packet\n", hash);
			}
		}
		catch(std::out_of_range & e) {
			DOLOG(dl, "SCTP(%s): truncated\n", their_addr.to_str().c_str());
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
