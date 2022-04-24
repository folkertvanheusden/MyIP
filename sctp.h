// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <functional>
#include <map>
#include <shared_mutex>

#include "buffer_in.h"
#include "buffer_out.h"
#include "ip_protocol.h"
#include "packet.h"
#include "utils.h"


class icmp;

class sctp : public ip_protocol
{
private:
	class sctp_session {
	public:
		any_addr their_addr;

		uint32_t their_verification_tag { 0 };
		uint32_t my_verification_tag    { 0 };

		uint16_t their_port_number      { 0 };
		uint16_t my_port_number         { 0 };

		char     buffer[4096]           { 0 };

		uint64_t last_packet            { 0 };

		sctp_session(const any_addr & their_addr) : their_addr(their_addr) {
			last_packet = get_ms();
		}

		virtual ~sctp_session() {
		}

		void update_last_packet() {
			last_packet = get_ms();
		}

		uint64_t get_id_hash() {
			buffer_out temp;

			temp.add_any_addr (their_addr);
			temp.add_net_short(their_port_number);
			temp.add_net_short(my_port_number);

			// TODO: replace 123 by a sane seed
			return MurmurHash64A(temp.get_content(), temp.get_size(), 123);
		}
	};

	// uint64_t: sctp_session::get_id_hash
	std::map<uint64_t, sctp_session *> sessions;
	std::shared_mutex                  sessions_lock;

	icmp *const icmp_;

	std::map<int, uint64_t> allocated_ports;
	std::mutex              ports_lock;

	uint64_t *sctp_msgs        { nullptr };
	uint64_t *sctp_failed_msgs { nullptr };

	std::pair<uint16_t, buffer_in> get_parameter(buffer_in & chunk_payload);
	buffer_out                     init(sctp_session *const session, buffer_in & in);

public:
	sctp(stats *const s, icmp *const icmp_);
	virtual ~sctp();

	void add_handler(const int port, std::function<void(const any_addr &, int, const any_addr &, int, packet *, void *const pd)> h, void *const pd);
	void remove_handler(const int port);

	bool transmit_packet(const any_addr & dst_ip, const int dst_port, const any_addr & src_ip, const int src_port, const uint8_t *payload, const size_t pl_size);

	virtual void operator()() override;
};
