// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <time.h>
#include <openssl/hmac.h>

#include "buffer_in.h"
#include "ipv4.h"
#include "icmp.h"
#include "log.h"
#include "sctp.h"
#include "sctp_crc32c.h"
#include "utils.h"

// This code uses the 'buffer_in' object: it is a test for how well it is usable when
// implementing something like a protocol stack.
// Methods can be quite large as they're written *while* reading the RFC (4960).

// TODO:
// - session cleaner

// debug level
constexpr log_level_t dl = ll_info;

sctp::sctp(stats *const s, icmp *const icmp_) : ip_protocol(s, "sctp"), icmp_(icmp_)
{
	sctp_msgs        = s->register_stat("sctp_msgs");
	sctp_failed_msgs = s->register_stat("sctp_failed_msgs");

	get_random(state_cookie_key, sizeof state_cookie_key);
	state_cookie_key_timestamp = time(nullptr);

	for(int i=0; i<4; i++)
		ths.push_back(new std::thread(std::ref(*this)));
}

sctp::~sctp()
{
	stop_flag = true;

	for(auto & th : ths) {
		th->join();

		delete th;
	}

	for(auto & handler : listeners) {
		if (handler.second.deinit)
			handler.second.deinit();
	}

	for(auto & s : sessions)
		delete s.second;
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

	uint32_t my_initial_tsn = my_verification_tag;  // sane default
	get_random(reinterpret_cast<uint8_t *>(&my_initial_tsn), sizeof my_initial_tsn);

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

buffer_out sctp::chunk_gen_shutdown()
{
	buffer_out out;

	out.add_net_byte(7);  // SCTP SHUTDOWN
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

std::pair<sctp_data_handling_result_t, buffer_out> sctp::chunk_data(sctp_session *const s, buffer_in & chunk, buffer_out *const reply, std::function<bool(pstream *const sctp_, session *const s, buffer_in data)> & new_data_handler)
{
	sctp_session *session = reinterpret_cast<sctp_session *>(s);

	buffer_out out;

	sctp_data_handling_result_t result = dcb_abort;

	uint32_t current_tsn   = chunk.get_net_long();
	uint16_t stream_id_s   = chunk.get_net_short();
	uint16_t stream_seq_nr = chunk.get_net_short();
	uint32_t payload_protocol_identifier = chunk.get_net_long();
	uint32_t tsn_before    = session->get_their_tsn();

	if (current_tsn == session->get_their_tsn()) {
		int payload_size = chunk.get_n_bytes_left();

		session->inc_their_tsn(1);

		buffer_in temp(chunk.get_segment(payload_size));
		bool rc = new_data_handler(this, session, temp);

		if (rc)
			result = dcb_continue;
		else
			result = dcb_close;
	}
	else {
		DOLOG(dl, "SCTP[%lx]: out-of-order data received\n", session->get_hash());

		result = dcb_continue;
	}

	buffer_out chunk_out;

	chunk_out.add_net_byte(3);  // SACK
	chunk_out.add_net_byte(3);  // unfragmented message
	size_t length_offset = chunk_out.add_net_short(0, -1);  // place holder for length
	chunk_out.add_net_long(tsn_before);  // upto what TSN has all data been received, https://datatracker.ietf.org/doc/html/rfc4960#section-3.3.4
	chunk_out.add_net_long(4096 /* TODO */);  // receive window
	chunk_out.add_net_short(0);  // number of gap blocks
	chunk_out.add_net_short(0);  // duplicate TSN issues

	chunk_out.add_net_short(chunk_out.get_size(), length_offset);

	out.add_buffer_out(chunk_out);

	return { result, out };
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

		try {
			buffer_in b(p, size);

			uint16_t source_port         = b.get_net_short();  // their port
			uint16_t destination_port    = b.get_net_short();  // local port
			uint32_t my_verification_tag = b.get_net_long();
			uint32_t checksum            = b.get_net_long();

			uint64_t hash                = session::get_hash(their_addr, source_port, destination_port);

			DOLOG(dl, "SCTP[%lx]: source addr %s, source port %d, destination port %d, size: %d, verification tag: %08x\n", hash, their_addr.to_str().c_str(), source_port, destination_port, size, my_verification_tag);

			bool send_reply = true;

			buffer_out reply;

			reply.add_net_short(destination_port);
			reply.add_net_short(source_port);
			size_t their_verification_tag_offset = reply.add_net_long(-1, -1);  // will be 0 in INIT, will be replaced by their verifiation/initial tag
			size_t crc_offset = reply.add_net_long(0, -1);  // place-holder for crc

			bool   terminate_session = false;

			while(b.end_reached() == false) {
				uint8_t  type      = b.get_net_byte();
				uint8_t  flags     = b.get_net_byte();
				uint16_t len       = b.get_net_short();

				uint8_t  type_type = type & 63;
				uint8_t  type_unh  = type >> 6;  // what to do when it can not be processed

				if (len < 4) {
					DOLOG(dl, "SCTP[%lx]: chunk too short\n", hash);

					terminate_session = true;
					break;
				}

				buffer_in chunk    = b.get_segment(len - 4);

				DOLOG(dl, "SCTP[%lx]: type %d flags %d length %d\n", hash, type, flags, len);

				if (type == 0) {  // DATA
					DOLOG(dl, "SCTP[%lx]: DATA chunk of length %d\n", hash, chunk.get_n_bytes_left());

					std::function<bool(pstream *const ps, session *const s, buffer_in data)> new_data_handler = nullptr;

					{
						std::shared_lock<std::shared_mutex> lck(listeners_lock);

						auto it = listeners.find(destination_port);

						if (it != listeners.end())
							new_data_handler = it->second.new_data;
					}

					if (new_data_handler) {
						std::shared_lock<std::shared_mutex> lck(sessions_lock);

						auto it = sessions.find(hash);

						if (it != sessions.end()) {
							auto handling_result = chunk_data(it->second, chunk, &reply, new_data_handler);

							if (handling_result.first == dcb_abort) {
								// abort session...
								terminate_session = true;
								// ...after sending abort chunk
								reply.add_buffer_out(chunk_gen_abort());

								break;
							}
							else {
								reply.add_buffer_out(handling_result.second);

								if (handling_result.first == dcb_close) 
									reply.add_buffer_out(chunk_gen_shutdown());

								reply.add_net_long(it->second->get_their_verification_tag(), their_verification_tag_offset);
							}
						}
					}
					else {
						DOLOG(dl, "SCTP[%lx]: DATA: new_data_handler went away?\n", hash);

						reply.add_buffer_out(chunk_gen_abort());

						terminate_session = true;
					}
				}
				else if (type == 1) {  // INIT
					DOLOG(dl, "SCTP[%lx]: INIT chunk of length %d\n", hash, chunk.get_n_bytes_left());

					bool has_listener = false;

					{
						std::shared_lock<std::shared_mutex> lck(listeners_lock);

						auto it = listeners.find(destination_port);

						if (it != listeners.end())
							has_listener = true;
					}

					// also go through this when no listener is registered as we
					// need the initial verification tag of the other side
					uint32_t their_initial_verification_tag = 0;

					uint32_t my_new_verification_tag        = 0;

					// verification tag may not be 0
					do {
						get_random(reinterpret_cast<uint8_t *>(&my_new_verification_tag), sizeof my_new_verification_tag);
					} while(my_new_verification_tag == 0);

					buffer_out temp;
					chunk_init(hash, chunk, my_new_verification_tag, 4096 /* TODO */, their_addr, source_port, destination_port, &temp, &their_initial_verification_tag);

					reply.add_net_long(their_initial_verification_tag, their_verification_tag_offset);

					if (has_listener)
						reply.add_buffer_out(temp);
					else {
						DOLOG(dl, "SCTP[%lx]: no listener for port %d\n", hash, destination_port);

						reply.add_buffer_out(chunk_gen_abort());

						terminate_session = true;
					}
				}
				else if (type == 4) {  // HEARTBEAT (-request)
					DOLOG(dl, "SCTP[%lx]: heartbeat request received\n", hash);

					reply.add_buffer_out(chunk_heartbeat_request(chunk));
				}
				else if (type == 6) {  // ABORT
					DOLOG(dl, "SCTP[%lx]: abort request received\n", hash);

					terminate_session = true;

					send_reply        = false;

					break;
				}
				else if (type == 10) {  // COOKIE ECHO
					bool     cookie_ok              = false;

					uint32_t their_verification_tag = 0;
					uint32_t their_initial_tsn      = 0;
					uint32_t my_initial_tsn         = 0;

					chunk_cookie_echo(chunk, their_addr, source_port, destination_port, &cookie_ok, &their_verification_tag, &their_initial_tsn, &my_initial_tsn);

					std::function<void(pstream *const ps, session *const s)> new_session_handler = nullptr;
					private_data *application_private_data = nullptr;

					{
						std::shared_lock<std::shared_mutex> lck(listeners_lock);

						auto it = listeners.find(destination_port);

						if (it != listeners.end()) {
							application_private_data = it->second.pd;
							new_session_handler      = it->second.new_session;
						}
						else {
							DOLOG(dl, "SCTP[%lx]: listener for port %d went away?\n", hash, destination_port);
						}
					}

					if (cookie_ok && new_session_handler) {
						// register session
						std::unique_lock<std::shared_mutex> lck(sessions_lock);

						if (sessions.find(hash) != sessions.end())
							DOLOG(dl, "SCTP[%lx]: session already on-going\n", hash);
						else {
							DOLOG(dl, "SCTP[%lx]: their initial tsn: %lu, my initial tsn: %lu\n", hash, their_initial_tsn, my_initial_tsn);

							sctp_session *s = new sctp_session(this, their_addr, source_port, pkt->get_dst_addr(), destination_port, their_initial_tsn, my_initial_tsn, their_verification_tag, application_private_data);
							new_session_handler(this, s);

							sessions.insert({ hash, s });
						}

						// send ack
						reply.add_buffer_out(chunk_gen_cookie_ack());

						DOLOG(dl, "SCTP[%lx]: COOKIE ECHO ACK\n", hash);
					}
					else {
						// send deny
						reply.add_buffer_out(chunk_gen_abort());

						DOLOG(dl, "SCTP[%lx]: ABORT\n", hash);

						terminate_session = true;
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

				DOLOG(dl, "SCTP[%lx]: CRC32c over %zu bytes: %08lx\n", hash, reply.get_size(), crc32c);

				// transmit 'reply' (0x84 is SCTP protocol number)
				if (transmit_packet(their_addr, pkt->get_dst_addr(), reply.get_content(), reply.get_size()) == false)
					DOLOG(ll_info, "SCTP[%lx]: failed to transmit reply packet\n", hash);
			}

			if (terminate_session) {
				std::unique_lock<std::shared_mutex> lck(sessions_lock);

				sessions.erase(hash);
			}
		}
		catch(std::out_of_range & e) {
			DOLOG(dl, "SCTP(%s): truncated\n", their_addr.to_str().c_str());
		}

		delete pkt;
	}
}

bool sctp::transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t *payload, const size_t pl_size)
{
	// 0x84 is SCTP protocol number
	return idev->transmit_packet(dst_ip, src_ip, 0x84, payload, pl_size, nullptr);
}

bool sctp::send_data(session *const s_in, buffer_in & payload)
{
	bool     ok          = true;

	sctp_session *s = reinterpret_cast<sctp_session *>(s_in);

	// TODO store these messages for resend

	while(payload.end_reached() == false) {
		buffer_out out;

		out.add_net_short(s->get_my_port());
		out.add_net_short(s->get_their_port());
		out.add_net_long(s->get_their_verification_tag());
		size_t crc_offset = out.add_net_long(0, -1);  // place-holder for crc

		// add payload
		out.add_net_byte(0);  // chunk type 'DATA'
		out.add_net_byte(3);  // unfragmented data
		// length of payload in this chunk
		int n_bytes_to_add = std::min(payload.get_n_bytes_left(), idev->get_max_packet_size() - 50 /* TODO */);
		out.add_net_short(n_bytes_to_add + 16);
		// TSN
		out.add_net_long(s->get_my_tsn());
		s->inc_my_tsn(1);
		//
		out.add_net_short(0);  // stream identifier s
		out.add_net_short(s->get_my_stream_sequence_nr());  // stream sequence number
		s->inc_my_stream_sequence_nr();
		out.add_net_long(0);  // payload protocol identifier
		// payload:
		buffer_in temp_payload = payload.get_segment(n_bytes_to_add);
		out.add_buffer_in(temp_payload);

		out.add_padding(4);

		// calculate & set crc in 'reply'
		uint32_t crc32c = generate_crc32c(out.get_content(), out.get_size());
		out.add_net_long(crc32c, crc_offset);

		// transmit 'reply'
		if (transmit_packet(s->get_their_addr(), s->get_my_addr(), out.get_content(), out.get_size()) == false) {
			ok = false;

			DOLOG(ll_info, "SCTP[%lx]: failed to transmit send_data packet\n", s->get_hash());

			break;
		}
	}

	return ok;
}

bool sctp::send_data(session *const s, const uint8_t *const data, const size_t len)
{
	buffer_in b(data, len);

	return send_data(s, b);
}

void sctp::add_handler(const int port, port_handler_t & sph)
{
	if (sph.init)
		sph.init();

	std::unique_lock<std::shared_mutex> lck(listeners_lock);

	listeners.insert({ port, sph });
}

void sctp::end_session(session *const s_in)
{
	sctp_session *s = reinterpret_cast<sctp_session *>(s_in);

	buffer_out out;

	out.add_net_short(s->get_my_port());
	out.add_net_short(s->get_their_port());
	out.add_net_long(s->get_their_verification_tag());

	size_t crc_offset = out.add_net_long(0, -1);  // place-holder for crc

	out.add_buffer_out(chunk_gen_shutdown());

	// calculate & set crc in 'reply'
	uint32_t crc32c = generate_crc32c(out.get_content(), out.get_size());
	out.add_net_long(crc32c, crc_offset);

	// transmit 'reply' (0x84 is SCTP protocol number)
	if (transmit_packet(s->get_their_addr(), s->get_my_addr(), out.get_content(), out.get_size()) == false)
		DOLOG(ll_info, "SCTP[%lx]: failed to transmit shutdown packet\n", s->get_hash());
}
