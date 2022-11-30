// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <functional>
#include <map>
#include <shared_mutex>

#include "application.h"
#include "buffer_in.h"
#include "buffer_out.h"
#include "hash.h"
#include "ip_protocol.h"
#include "packet.h"
#include "pstream.h"
#include "session.h"


class icmp;

// dcb: data-call-back
typedef enum { dcb_close, dcb_abort, dcb_continue } sctp_data_handling_result_t;

class sctp : public ip_protocol, public pstream
{
public:
	class sctp_session : public session {
	private:
		uint32_t my_tsn                 { 0 };
		uint32_t their_tsn              { 0 };
		uint16_t my_stream_sequence_nr  { 0 };
		uint32_t their_verification_tag { 0 };
	
	public:
		sctp_session(pstream *const ps, const any_addr & their_addr, const uint16_t their_port, const any_addr & my_addr, const uint16_t my_port, const uint32_t their_tsn, const uint32_t my_tsn, const uint32_t their_verification_tag, private_data *const pd) :
			session(ps, my_addr, my_port, their_addr, their_port, pd),
			my_tsn(my_tsn), their_tsn(their_tsn),
			their_verification_tag(their_verification_tag)
		{
		}

		virtual ~sctp_session() {
		}

		uint32_t get_my_tsn() const {
			return my_tsn;
		}

		void inc_my_tsn(const uint32_t how_much) {
			my_tsn += how_much;
		}

		uint32_t get_their_tsn() const {
			return their_tsn;
		}

		void inc_their_tsn(const uint32_t how_much) {
			their_tsn += how_much;
		}

		uint16_t get_my_stream_sequence_nr() const {
			return my_stream_sequence_nr;
		}

		void inc_my_stream_sequence_nr() {
			my_stream_sequence_nr++;
		}

		uint32_t get_their_verification_tag() const {
			return their_verification_tag;
		}

		std::string get_state_name() const {
			return "established";
		}
	};

private:
	std::shared_mutex                  sessions_lock;
	std::map<uint64_t, sctp_session *> sessions;

	uint8_t state_cookie_key[32]       { 0 };
	time_t  state_cookie_key_timestamp { 0 };

	icmp *const icmp_;

	std::shared_mutex                  listeners_lock;
	std::map<int, port_handler_t>      listeners;

	uint64_t *sctp_msgs        { nullptr };
	uint64_t *sctp_failed_msgs { nullptr };

	std::pair<uint16_t, buffer_in> get_parameter(const uint64_t hash, buffer_in & chunk_payload);

	buffer_out generate_state_cookie(const any_addr & their_addr, const int their_port, const int local_port, const uint32_t my_verification_tag, const uint32_t their_initial_tsn, const uint32_t my_initial_tsn);
	buffer_out chunk_gen_abort();
	buffer_out chunk_gen_cookie_ack();
	buffer_out chunk_gen_shutdown();
	buffer_out chunk_heartbeat_request(buffer_in & chunk_payload);

	void chunk_init(const uint64_t hash, buffer_in & chunk_payload, const uint32_t my_verification_tag, const uint32_t buffer_size, const any_addr & their_addr, const int their_port, const int local_port, buffer_out *const out, uint32_t *const initiate_tag);
	void chunk_cookie_echo(buffer_in & chunk_payload, const any_addr & their_addr, const int their_port, const int local_port, bool *const ok, uint32_t *const my_verification_tag, uint32_t *const their_initial_tsn, uint32_t *const my_initial_tsn);
	std::pair<sctp_data_handling_result_t, buffer_out> chunk_data(sctp_session *const s, buffer_in & chunk, buffer_out *const reply, std::function<bool(pstream *const sctp_, session *const s, buffer_in data)> & new_data_handler);

	bool transmit_packet(const any_addr & dst_ip, const any_addr & src_ip, const uint8_t *payload, const size_t pl_size);

public:
	sctp(stats *const s, icmp *const icmp_);
	virtual ~sctp();

	void add_handler(const int port, port_handler_t & sph);

	bool send_data(session *const s, buffer_in & payload);
	bool send_data(session *const s, const uint8_t *const data, const size_t len) override;

	void end_session(session *const ts) override;

	virtual void operator()() override;
};
