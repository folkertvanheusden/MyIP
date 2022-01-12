// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <atomic>
#include <chrono>
#include <inttypes.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "tcp.h"
#include "ipv4.h"
#include "utils.h"

using namespace std::chrono_literals;

const char *const states[] = { "closed", "listen", "syn_rcvd", "syn_sent", "established", "fin_wait_1", "fin_wait_2", "close_wait", "last_ack", "closing", "time_wait", "rst_act" };

#define FLAG_CWR (1 << 7)
#define FLAG_ECE (1 << 6)
#define FLAG_URG (1 << 5)
#define FLAG_ACK (1 << 4)
#define FLAG_PSH (1 << 3)
#define FLAG_RST (1 << 2)
#define FLAG_SYN (1 << 1)
#define FLAG_FIN (1 << 0)

void free_tcp_session(tcp_session_t *const p)
{
	free(p->unacked);

	delete p->p;

	delete p;
}

char *flags_to_str(uint8_t flags)
{
	char *out = (char *)calloc(1, 128);

	if (flags & FLAG_CWR)
		strcat(out, "CWR,");
	if (flags & FLAG_ECE)
		strcat(out, "ECE,");
	if (flags & FLAG_URG)
		strcat(out, "URG,");
	if (flags & FLAG_ACK)
		strcat(out, "ACK,");
	if (flags & FLAG_PSH)
		strcat(out, "PSH,");
	if (flags & FLAG_RST)
		strcat(out, "RST,");
	if (flags & FLAG_SYN)
		strcat(out, "SYN,");
	if (flags & FLAG_FIN)
		strcat(out, "FIN,");

	return out;
}

tcp::tcp(stats *const s) : ip_protocol(s, "tcp")
{
	tcp_packets = s->register_stat("tcp_packets");
	tcp_errors = s->register_stat("tcp_errors", "1.3.6.1.2.1.6.7");  // tcpAttemptFails
	tcp_succ_estab = s->register_stat("tcp_succ_estab");
	tcp_internal_err = s->register_stat("tcp_internal_err");
	tcp_syn = s->register_stat("tcp_syn");
	tcp_new_sessions = s->register_stat("tcp_new_sessions");
	tcp_sessions_rem = s->register_stat("tcp_sessions_rem");
	tcp_sessions_to = s->register_stat("tcp_sessions_to");
	tcp_sessions_closed_1 = s->register_stat("tcp_sessions_closed1");
	tcp_sessions_closed_2 = s->register_stat("tcp_sessions_closed2");
	tcp_rst = s->register_stat("tcp_rst");
	tcp_cur_n_sessions = s->register_stat("tcp_cur_n_sessions");

	th = new std::thread(std::ref(*this));
}

tcp::~tcp()
{
	stop_flag = true;

	th->join();
	delete th;
}

int rel_seqnr(const tcp_session_t *const ts, const bool mine, const uint32_t nr)
{
	return mine ? nr - ts->initial_my_seq_nr : nr - ts->initial_their_seq_nr;
}

void tcp::send_segment(tcp_session_t *const ts, const uint64_t session_id, const any_addr & my_addr, const int my_port, const any_addr & peer_addr, const int peer_port, const int org_len, const uint8_t flags, const uint32_t ack_to, uint32_t *const my_seq_nr, const uint8_t *const data, const size_t data_len)
{
	char *flag_str = flags_to_str(flags);
	DOLOG(debug, "TCP[%012" PRIx64 "]: Sending segment (flags: %02x (%s)), ack to: %u, my seq: %u, len: %zu)\n", session_id, flags, flag_str, rel_seqnr(ts, false, ack_to), my_seq_nr ? rel_seqnr(ts, true, *my_seq_nr) : -1, data_len);
	free(flag_str);

	if (!idev) {
		DOLOG(debug, "TCP[%012" PRIx64 "]: Dropping packet, no physical device assigned (yet)\n", session_id);
		return;
	}

	size_t temp_len = 20 + data_len;
	uint8_t *temp = new uint8_t[temp_len];

	temp[0] = my_port >> 8;
	temp[1] = my_port & 255;
	temp[2] = peer_port >> 8;
	temp[3] = peer_port & 255;

	if (my_seq_nr) {
		temp[4] = *my_seq_nr >> 24;
		temp[5] = *my_seq_nr >> 16;
		temp[6] = *my_seq_nr >>  8;
		temp[7] = *my_seq_nr;
	}
	else {
		temp[4] = temp[5] = temp[6] = temp[7] = 0;
	}

	temp[8] = ack_to >> 24; // ack
	temp[9] = ack_to >> 16;
	temp[10] = ack_to >> 8;
	temp[11] = ack_to;

	temp[12] = 5 << 4; // header len
	temp[13] = flags;

	if (data_len) {
		temp[14] = data_len >> 8;
		temp[15] = data_len & 255;
	}
	else {
		temp[14] = org_len >> 8;
		temp[15] = org_len & 255;
	}

	temp[16] = temp[17] = 0; // checksum
	temp[18] = temp[19] = 0; // urgent pointer

	if (data_len)
		memcpy(&temp[20], data, data_len);

	uint16_t checksum = tcp_udp_checksum(peer_addr, my_addr, true, temp, temp_len);

	temp[16] = checksum >> 8;
	temp[17] = checksum;

	idev->transmit_packet(peer_addr, my_addr, 0x06, temp, temp_len, nullptr);

	delete [] temp;

	if (my_seq_nr) {
		(*my_seq_nr) += data_len;

		if ((flags & FLAG_FIN) || (flags & FLAG_SYN))
			(*my_seq_nr)++;
	}

	ts->last_pkt = get_us();
}

std::optional<tcp_port_handler_t> tcp::get_lock_listener(const int dst_port, const uint64_t id)
{
	listeners_lock.lock();

	auto cb_it = listeners.find(dst_port);

	if (cb_it == listeners.end()) {
		DOLOG(info, "TCP[%012" PRIx64 "]: no listener for that (%d) port\n", id, dst_port);

		return { };
	}

	return cb_it->second;
}

void tcp::release_listener_lock()
{
	listeners_lock.unlock();
}

uint64_t hash_address(const any_addr & a, const int local_port, const int peer_port)
{
	return a.get_hash() ^ (uint64_t(local_port) << 32) ^ (uint64_t(peer_port) << 48);
}

void tcp::set_state(tcp_session_t *const session, const tcp_state_t new_state)
{
	DOLOG(debug, "TCP[%012" PRIx64 "]: changing state from %s to %s\n", session->id, states[session->state], states[new_state]);

	session->state = new_state;
	session->state_since = time(nullptr);

	session->state_changed.notify_all();
}

void tcp::packet_handler(const packet *const pkt, std::atomic_bool *const finished_flag)
{
	set_thread_name("myip-pkt-handler");

	const uint8_t *const p = pkt->get_data();
	const int size = pkt->get_size();

	if (size < 20) {
		DOLOG(info, "TCP: packet too short [IC]\n");
		delete pkt;
		stats_inc_counter(tcp_errors);
		*finished_flag = true;
		return;
	}

	// not verifying checksum: assuming that link layer takes care
	// of corruptions

	bool flag_fin = p[13] & 1;
	bool flag_syn = p[13] & 2;
	bool flag_rst = p[13] & 4;
	bool flag_ack = p[13] & 16;

	uint16_t src_port = (p[0] << 8) | p[1];
	uint16_t dst_port = (p[2] << 8) | p[3];

	uint32_t their_seq_nr = (p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7];
	uint32_t ack_to = (p[8] << 24) | (p[9] << 16) | (p[10] << 8) | p[11];

	int header_size = (p[12] >> 4) * 4;

	int win_size = (p[14] << 8) | p[15];

	auto src = pkt->get_src_addr();
	uint64_t id = hash_address(src, dst_port, src_port);

	char *flag_str = flags_to_str(p[13]);
	DOLOG(debug, "TCP[%012" PRIx64 "]: packet [%s]:%d->[%s]:%d, flags: %02x (%s), their seq: %u, ack to: %u, chksum: 0x%04x, size: %d\n", id, src.to_str().c_str(), src_port, pkt->get_dst_addr().to_str().c_str(), dst_port, p[13], flag_str, their_seq_nr, ack_to, (p[16] << 8) | p[17], size);
	free(flag_str);

	sessions_lock.lock();

	auto cur_it = sessions.find(id);

	if (cur_it == sessions.end()) {
		if (flag_syn) {  // MUST start with SYN
			tcp_session_t *new_session = new tcp_session_t();

			new_session->state = tcp_listen;
			new_session->state_since = 0;

			get_random((uint8_t *)&new_session->my_seq_nr, sizeof new_session->my_seq_nr);
			new_session->initial_my_seq_nr = new_session->my_seq_nr; // for logging relative(!) sequence numbers

			new_session->initial_their_seq_nr = their_seq_nr;
			new_session->their_seq_nr = their_seq_nr + 1;

			new_session->id = id;

			new_session->is_client = false;

			new_session->unacked = nullptr;
			new_session->unacked_start_seq_nr = 0;
			new_session->unacked_size = 0;
			new_session->fin_after_unacked_empty = false;

			new_session->window_size = win_size;

			new_session->org_src_addr = pkt->get_src_addr();
			new_session->org_src_port = src_port;

			new_session->org_dst_addr = pkt->get_dst_addr();
			new_session->org_dst_port = dst_port;

			new_session->p = nullptr;
			new_session->t = this;

			sessions.insert({ id, new_session });

			stats_set(tcp_cur_n_sessions, sessions.size());

			stats_inc_counter(tcp_new_sessions);

			DOLOG(debug, "TCP[%012" PRIx64 "]: ...is a new session (initial my seq nr: %u, their: %u)\n", id, new_session->initial_my_seq_nr, new_session->initial_their_seq_nr);

			cur_it = sessions.find(id);
		}
		else {
			sessions_lock.unlock();
			DOLOG(debug, "TCP[%012" PRIx64 "]: new session which does not start with SYN [IC]\n", id);
			delete pkt;
			stats_inc_counter(tcp_errors);
			*finished_flag = true;
			return;
		}
	}

	tcp_session_t *const cur_session = cur_it->second;

	cur_session->last_pkt = get_us();

	DOLOG(debug, "TCP[%012" PRIx64 "]: start processing TCP segment, state: %s, my seq nr %d, opponent seq nr %d\n", id, states[cur_session->state], rel_seqnr(cur_session, true, cur_session->my_seq_nr), rel_seqnr(cur_session, false, cur_session->their_seq_nr));
	cur_session->tlock.lock();

	cur_it->second->window_size = std::max(1, win_size);

	bool fail = false;
	bool delete_entry = false;

	if (header_size > size) {
		DOLOG(info, "TCP[%012" PRIx64 "]: header with options > packet size [F]\n", id);
		fail = true;
	}

	if (!fail) {
		if (flag_rst) {
			if (cur_session->state >= tcp_syn_rcvd) {
				DOLOG(debug, "TCP[%012" PRIx64 "]: received RST: session setup aborted\n", id);
				set_state(cur_session, tcp_closing);
				delete_entry = true;
			}		
			else {
				DOLOG(debug, "TCP[%012" PRIx64 "]: unexpected RST\n", id);
			}
		}

		if (flag_syn && !delete_entry) {
			stats_inc_counter(tcp_syn);

			// tcp_syn_rcvd: opponent may not have received the syn,ack reply
			if (cur_session->state == tcp_listen || cur_session->state == tcp_syn_rcvd) {
				DOLOG(debug, "TCP[%012" PRIx64 "]: received SYN, send SYN + ACK\n", id);
				// send SYN + ACK
				send_segment(cur_session, id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, FLAG_SYN | FLAG_ACK, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0);

				set_state(cur_session, tcp_syn_rcvd);
			}
			else if (cur_session->state != tcp_syn_sent) { // not a client?
				DOLOG(debug, "TCP[%012" PRIx64 "]: unexpected SYN\n", id);
			}
		}

		if (flag_ack && !delete_entry) {
			if (cur_session->state == tcp_syn_sent) { // new session from a client
				cur_session->initial_their_seq_nr = their_seq_nr;
				cur_session->their_seq_nr = their_seq_nr + 1;

				DOLOG(debug, "TCP[%012" PRIx64 "]: received ACK%s: session established, their seq: %u, my seq: %u\n", id, flag_syn ? " and SYN" : "", cur_session->their_seq_nr, cur_session->my_seq_nr);

				send_segment(cur_session, cur_session->id, cur_session->org_src_addr, cur_session->org_src_port, cur_session->org_dst_addr, cur_session->org_dst_port, win_size, FLAG_ACK, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0);

//				cur_session->my_seq_nr += 1;

				set_state(cur_session, tcp_established);
			}
			// listener (server)
			else if (cur_session->state == tcp_syn_rcvd) {
				DOLOG(debug, "TCP[%012" PRIx64 "]: received ACK: session is established\n", id);
				set_state(cur_session, tcp_established);

				stats_inc_counter(tcp_succ_estab);

				auto cb = get_lock_listener(dst_port, id);

				if (cb.has_value()) {
					if (cb.value().new_session && cb.value().new_session(cur_session, pkt, cb.value().pd) == false) {
						DOLOG(debug, "TCP[%012" PRIx64 "]: session terminated by layer 7\n", id);
						fail = true;
					}
				}
				else {
					fail = true;
				}

				release_listener_lock();
			}
			else if (cur_session->state == tcp_last_ack) {
				DOLOG(debug, "TCP[%012" PRIx64 "]: received ACK: session is finished\n", id);
				set_state(cur_session, tcp_listen);  // tcp_closed really
				delete_entry = true;
			}
			// opponent acknowledges the reception of a bit of data
			else if (cur_session->state == tcp_established) {
				int ack_n = ack_to - cur_session->unacked_start_seq_nr;

				if (ack_n > 0 && cur_session->unacked_size > 0) {
					DOLOG(debug, "TCP[%012" PRIx64 "]: ack to: %u (last seq nr %u), size: %d), unacked currently: %zu\n", id, rel_seqnr(cur_session, true, ack_to), rel_seqnr(cur_session, true, cur_session->my_seq_nr), ack_n, cur_session->unacked_size);

					// delete acked
					int left_n = cur_session->unacked_size - ack_n;
					if (left_n > 0)
						memmove(&cur_session->unacked[0], &cur_session->unacked[ack_n], left_n);
					else if (left_n < 0) {
						DOLOG(warning, "TCP[%012" PRIx64 "]: ack underrun? %d\n", id, left_n);
						// terminate this invalid session
						// can happen for data coming in after finished
						delete_entry = fail = true;
					}

					cur_session->unacked_size -= ack_n;
					cur_session->unacked_start_seq_nr += ack_n;

					DOLOG(debug, "TCP[%012" PRIx64 "]: unacked left: %zu, fin after empty: %d\n", id, cur_session->unacked_size, cur_session->fin_after_unacked_empty);

					cur_session->my_seq_nr += ack_n;

					if (cur_session->unacked_size == 0 && cur_session->fin_after_unacked_empty) {
						DOLOG(debug, "TCP[%012" PRIx64 "]: unacked buffer empy, FIN\n", id);

						send_segment(cur_session, cur_session->id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, FLAG_ACK | FLAG_FIN /* ACK, FIN */, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0);

						set_state(cur_session, tcp_fin_wait_1);
					}
				}

				unacked_cv.notify_all();
			}
			else {
				DOLOG(debug, "TCP[%012" PRIx64 "]: unexpected ACK\n", id);
			}

			cur_session->data_since_last_ack = 0;
		}

		if (flag_fin) {
			if (cur_session->state == tcp_established) {
				DOLOG(debug, "TCP[%012" PRIx64 "]: received FIN\n", id);

				DOLOG(debug, "TCP[%012" PRIx64 "]: cur_session->their_seq_nr %ld, their: %ld\n", id, cur_session->their_seq_nr, their_seq_nr);

				cur_session->seq_for_fin_when_all_received = their_seq_nr;
				cur_session->flag_fin_when_all_received = true;
			}
			else {
				DOLOG(debug, "TCP[%012" PRIx64 "]: unexpected FIN\n", id);
			}
		}

		if (cur_session->flag_fin_when_all_received && cur_session->seq_for_fin_when_all_received == cur_session->their_seq_nr) {
			DOLOG(debug, "TCP[%012" PRIx64 "]: ack FIN after all data has been received\n", id);

			// send ACK + FIN
			if (cur_session->is_client)
				send_segment(cur_session, id, cur_session->org_src_addr, cur_session->org_src_port, cur_session->org_dst_addr, cur_session->org_dst_port, win_size, FLAG_ACK | FLAG_FIN, cur_session->their_seq_nr + 1, &cur_session->my_seq_nr, nullptr, 0);
			else
				send_segment(cur_session, id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, FLAG_ACK | FLAG_FIN, cur_session->their_seq_nr + 1, &cur_session->my_seq_nr, nullptr, 0);
		}
	}

	// process payload
	int data_len = size - header_size;
	if (data_len > 0 && fail == false) {
		DOLOG(debug, "TCP[%012" PRIx64 "]: packet len %d, header size: %d, payload size: %d\n", id, size, header_size, data_len);

		DOLOG(debug, "TCP[%012" PRIx64 "]: %s\n", id, std::string((const char *)&p[header_size], data_len).c_str());

		if (their_seq_nr == cur_session->their_seq_nr) {
			const uint8_t *data_start = &p[header_size];

//			std::string content = bin_to_text(data_start, data_len);
//			DOLOG(debug, "TCP[%012" PRIx64 "]: Received content: %s\n", id, content.c_str());

			auto cb = get_lock_listener(dst_port, id);

			if (cb.has_value()) {
				try {
					if (cb.value().new_data(cur_session, pkt, data_start, data_len, cb.value().pd) == false) {
						DOLOG(ll_error, "TCP[%012" PRIx64 "]: layer 7 indicated an error\n", id);
						fail = true;
					}
				}
				catch(...) {
					DOLOG(ll_error, "TCP[%012" PRIx64 "]: EXCEPTION IN new_data()\n", id);
					fail = true;
				}
			}
			else {
				fail = true;
			}

			release_listener_lock();

			if (fail == false) {
				cur_session->their_seq_nr += data_len;  // TODO handle missing segments

				// will be acked in the 'unacked_sender'-thread
				if (cur_session->unacked_size == 0) {
					DOLOG(debug, "TCP[%012" PRIx64 "]: acknowledging received content\n", id);

					if (cur_session->is_client)
						send_segment(cur_session, id, cur_session->org_src_addr, cur_session->org_src_port, cur_session->org_dst_addr, cur_session->org_dst_port, win_size, FLAG_ACK, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0);
					else
						send_segment(cur_session, id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, FLAG_ACK, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0);
				}
			}
		}
		else {
			DOLOG(info, "TCP[%012" PRIx64 "]: unexpected sequence nr %u, expected: %u\n", id, rel_seqnr(cur_session, false, their_seq_nr), rel_seqnr(cur_session, false, cur_session->their_seq_nr));

			uint32_t ack_to = cur_session->their_seq_nr >= their_seq_nr ? their_seq_nr : cur_session->their_seq_nr;

			if (cur_session->is_client)
				send_segment(cur_session, id, cur_session->org_src_addr, cur_session->org_src_port, cur_session->org_dst_addr, cur_session->org_dst_port, win_size, FLAG_ACK, ack_to, &cur_session->my_seq_nr, nullptr, 0);
			else
				send_segment(cur_session, id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, FLAG_ACK, ack_to, &cur_session->my_seq_nr, nullptr, 0);
		}

		unacked_cv.notify_all();
	}

	if (fail) {
		auto cb = get_lock_listener(dst_port, id);

		if (cb.has_value())
			cb.value().session_closed_1(cur_session, cb.value().pd);

		release_listener_lock();

		stats_inc_counter(tcp_errors);

		cur_session->unacked_sent_cv.notify_all();

		delete_entry = true;

		DOLOG(info, "TCP[%012" PRIx64 "]: sending fail packet [IC]\n", id);
		if (cur_session->is_client)
			send_segment(cur_session, id, cur_session->org_src_addr, cur_session->org_src_port, cur_session->org_dst_addr, cur_session->org_dst_port, win_size, FLAG_RST | FLAG_ACK, their_seq_nr + 1, nullptr, nullptr, 0);
		else
			send_segment(cur_session, id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, FLAG_RST | FLAG_ACK, their_seq_nr + 1, nullptr, nullptr, 0);
	}

	cur_session->tlock.unlock();

	sessions_lock.unlock();

	if (delete_entry) {
		DOLOG(info, "TCP[%012" PRIx64 "]: cleaning up session\n", id);

		sessions_lock.lock();

		cur_it = sessions.find(id);

		if (cur_it != sessions.end()) {
			tcp_session_t *pointer = cur_it->second;
			bool is_client = pointer->is_client;

			sessions.erase(cur_it);
			stats_set(tcp_cur_n_sessions, sessions.size());
			sessions_lock.unlock();

			// call session_closed_2
			int close_port = is_client ? pointer->org_src_port : pointer->org_dst_port;

			auto cb_org = get_lock_listener(close_port, id);

			if (cb_org.has_value())  // session not initiated here?
				cb_org.value().session_closed_2(pointer, cb_org.value().pd);
			else
				DOLOG(info, "TCP[%012" PRIx64 "]: port %d not known\n", id, close_port);

			release_listener_lock();

			// clean-up
			free_tcp_session(pointer);
		}
		else {
			sessions_lock.unlock();
		}

		stats_inc_counter(tcp_sessions_rem);
	}

	delete pkt;

	*finished_flag = true;
}

void tcp::session_cleaner()
{
	set_thread_name("myip-tcp-clnr");

	while(!stop_flag) {
		using namespace std::chrono_literals;

		// TODO: langere wachttijd en wakker maken elders als state != established gezet wordt
		std::unique_lock<std::mutex> lck(sessions_lock);
		if (sessions_cv.wait_for(lck, 1s) == std::cv_status::no_timeout)
			DOLOG(debug, "tcp-clnr woke-up after ack\n");

		// find t/o'd sessions
		uint64_t now = get_us();

		for(auto it = sessions.cbegin(); it != sessions.cend();) {
			uint64_t age = (now - it->second->last_pkt) / 1000000;

			if (age >= session_timeout || it->second->state > tcp_established) {
				if (it->second->state > tcp_established)
					DOLOG(debug, "TCP[%012" PRIx64 "]: session closed (state: %s)\n", it->first, states[it->second->state]);
				else
					DOLOG(debug, "TCP[%012" PRIx64 "]: session timed out\n", it->first);

				// call session_closed
				auto cb = get_lock_listener(it->second->org_dst_port, it->first);

				if (cb.has_value()) {  // session not initiated here?
					cb.value().session_closed_1(it->second, cb.value().pd);
					cb.value().session_closed_2(it->second, cb.value().pd);
				}

				release_listener_lock();

				// clean-up
				free_tcp_session(it->second);

				it = sessions.erase(it);
				stats_set(tcp_cur_n_sessions, sessions.size());

				stats_inc_counter(tcp_sessions_to);
			}
			else if (it->second->state == tcp_time_wait && age >= 2) {
				DOLOG(debug, "TCP[%012" PRIx64 "]: session clean-up after tcp_time_wait state\n", it->first);

				if (it->second->is_client) {
					// forget client session
					tcp_clients.erase(it->second->org_src_port);
				}

				// clean-up
				free_tcp_session(it->second);

				it = sessions.erase(it);
				stats_set(tcp_cur_n_sessions, sessions.size());
			}
			else {
				++it;
			}
		}

		lck.unlock();
	}
}

void tcp::unacked_sender()
{
	set_thread_name("myip-tcp-us");

	while(!stop_flag) {
		using namespace std::chrono_literals;

		std::unique_lock<std::mutex> lck(sessions_lock);
		if (unacked_cv.wait_for(lck, 1s) == std::cv_status::no_timeout)
			DOLOG(debug, "tcp-unack woke-up after ack\n");

		// go through all sessions and find if any has segments to resend

		for(auto it = sessions.cbegin(); it != sessions.cend(); it++) {
			it->second->tlock.lock();

			bool notify = false;

			int to_send = std::min(it->second->window_size - it->second->data_since_last_ack, it->second->unacked_size);
			int packet_size = idev->get_max_packet_size() - 20;

			uint32_t resend_nr = it->second->my_seq_nr;

			for(int i=0; i<to_send; i += packet_size) {
				size_t send_n = std::min(packet_size, to_send - i);

				DOLOG(debug, "tcp-unack SEND %zu bytes for sequence nr %u (win size: %d, unacked: %zu, data since ack: %ld)\n", send_n, rel_seqnr(it->second, true, it->second->my_seq_nr), it->second->window_size, it->second->unacked_size, it->second->data_since_last_ack);

				if (it->second->is_client)
					send_segment(it->second, it->second->id, it->second->org_src_addr, it->second->org_src_port, it->second->org_dst_addr, it->second->org_dst_port, 0, FLAG_ACK, it->second->their_seq_nr, &resend_nr, &it->second->unacked[i], send_n);
				else
					send_segment(it->second, it->second->id, it->second->org_dst_addr, it->second->org_dst_port, it->second->org_src_addr, it->second->org_src_port, 0, FLAG_ACK, it->second->their_seq_nr, &resend_nr, &it->second->unacked[i], send_n);

				it->second->data_since_last_ack += send_n;

				notify = true;
			}

			it->second->tlock.unlock();

			if (notify)
				it->second->unacked_sent_cv.notify_one();
		}

		lck.unlock();
	}
}

// queue incoming packets
void tcp::operator()()
{
	set_thread_name("myip-tcp");

	std::thread *cleaner = new std::thread(&tcp::session_cleaner, this);

	std::thread *unacked_sender = new std::thread(&tcp::unacked_sender, this);

	std::vector<tcp_packet_handle_thread_t *> threads;

	while(!stop_flag) {
		auto po = pkts->get(500);
		if (!po.has_value())
			continue;

		const packet *pkt = po.value();

		stats_inc_counter(tcp_packets);

		tcp_packet_handle_thread_t *handler_data = new tcp_packet_handle_thread_t;
		handler_data->finished_flag = false;

		handler_data->th = new std::thread(&tcp::packet_handler, this, pkt, &handler_data->finished_flag);

		threads.push_back(handler_data);

		for(size_t i=0; i<threads.size();) {
			if (threads.at(i)->finished_flag) {
				threads.at(i)->th->join();
				delete threads.at(i)->th;
				delete threads.at(i);

				threads.erase(threads.begin() + i);
			}
			else {
				i++;
			}
		}

		sessions_cv.notify_all();
	}

	for(auto t : threads) {
		t->th->join();
		delete t->th;
		delete t;
	}

	unacked_sender->join();
	delete unacked_sender;

	cleaner->join();
	delete cleaner;
}

void tcp::add_handler(const int port, tcp_port_handler_t & tph)
{
	if (tph.init)
		tph.init();

	listeners_lock.lock();

	listeners.insert({ port, tph });

	listeners_lock.unlock();
}

void tcp::send_data(tcp_session_t *const ts, const uint8_t *const data, const size_t len)
{
	uint64_t internal_id = get_us();

	DOLOG(debug, "TCP[%012" PRIx64 "]: send frame, %zu bytes, internal id: %lu, %lu packets\n", ts->id, len, internal_id, (len + ts->window_size - 1) / ts->window_size);
	DOLOG(debug, "TCP[%012" PRIx64 "]: %s\n", ts->id, std::string((const char *)data, len).c_str());

	for(;;) {
		// lock for unacked and for my_seq_nr
		std::unique_lock<std::mutex> lck(ts->tlock);

		if (ts->unacked_size < 1024 * 1024)  // max 1MB queued
			break;

		if (ts->state != tcp_established) {
			DOLOG(debug, "TCP[%012" PRIx64 "]: send_data interrupted by session end\n", ts->id);
			break;
		}

		ts->unacked_sent_cv.wait_for(lck, 100ms);

		DOLOG(debug, "TCP[%012" PRIx64 "]: unacked-buffer full\n", ts->id);
	}

	if (ts->state == tcp_established) {
		std::unique_lock<std::mutex> lck(ts->tlock);

		if (ts->unacked_size == 0)
			ts->unacked_start_seq_nr = ts->my_seq_nr;

		ts->unacked = (uint8_t *)realloc(ts->unacked, ts->unacked_size + len);
		memcpy(&ts->unacked[ts->unacked_size], data, len);
		ts->unacked_size += len;
	}

	unacked_cv.notify_all();
}

// this method requires tcp_session_t to be already locked
void tcp::end_session(tcp_session_t *const ts)
{
	if (ts->unacked_size == 0) {
		DOLOG(debug, "TCP[%012" PRIx64 "]: end session, seq %u\n", ts->id, rel_seqnr(ts, true, ts->my_seq_nr));

		if (ts->is_client)
			send_segment(ts, ts->id, ts->org_src_addr, ts->org_src_port, ts->org_dst_addr, ts->org_dst_port, 1, FLAG_FIN, ts->their_seq_nr, &ts->my_seq_nr, nullptr, 0);
		else
			send_segment(ts, ts->id, ts->org_dst_addr, ts->org_dst_port, ts->org_src_addr, ts->org_src_port, 1, FLAG_FIN, ts->their_seq_nr, &ts->my_seq_nr, nullptr, 0);

		set_state(ts, tcp_fin_wait_1);
	}
	else {
		DOLOG(debug, "TCP[%012" PRIx64 "]: schedule end session, after %ld bytes\n", ts->id, ts->unacked_size);

		ts->fin_after_unacked_empty = true;
	}
}

int tcp::allocate_client_session(const std::function<bool(tcp_session_t *, const packet *pkt, const uint8_t *data, size_t len, private_data *)> & new_data, const std::function<void(tcp_session_t *, private_data *)> & session_closed_2, const any_addr & dst_addr, const int dst_port, private_data *const pd)
{
	tcp_port_handler_t handler { 0 };
	handler.new_data = new_data;
	handler.pd = pd;
	handler.session_closed_2 = session_closed_2;

	// generate id/port mapping
	uint16_t port = 0;

	// lock all sesions
	std::unique_lock<std::mutex> lck(sessions_lock);

	// allocate free port
	for(;;) {
		get_random((uint8_t *)&port, sizeof port);

		if (port > 1023 && port < 65535 && tcp_clients.find(port) == tcp_clients.end())
			break;
	}

	const any_addr src = idev->get_addr();

	uint64_t id = hash_address(dst_addr, port, dst_port);

	tcp_clients.insert({ port, id });

	// generate tcp session
	tcp_session_t *new_session = new tcp_session_t();
	new_session->state = tcp_syn_sent;
	new_session->state_since = time(nullptr);

	new_session->is_client = true;

	get_random((uint8_t *)&new_session->my_seq_nr, sizeof new_session->my_seq_nr);
	new_session->initial_my_seq_nr = new_session->my_seq_nr; // for logging relative(!) sequence numbers

	new_session->initial_their_seq_nr = 0;
	new_session->their_seq_nr = 0;

	new_session->id = id;

	new_session->unacked = nullptr;
	new_session->unacked_start_seq_nr = 0;
	new_session->unacked_size = 0;
	new_session->fin_after_unacked_empty = false;

	new_session->seq_for_fin_when_all_received = 0;

	new_session->window_size = idev->get_max_packet_size();

	new_session->org_src_addr = src;
	new_session->org_src_port = port;

	new_session->org_dst_addr = dst_addr;
	new_session->org_dst_port = dst_port;

	new_session->p = nullptr;
	new_session->t = this;

	stats_inc_counter(tcp_new_sessions);

	// connect id to session data
	sessions.insert({ id, new_session });
	stats_set(tcp_cur_n_sessions, sessions.size());

	add_handler(port, handler);

	lck.unlock();

	DOLOG(debug, "TCP[%012" PRIx64 "]: new client session, my seq nr: %u, local port: %d, destination port: %d\n", id, new_session->initial_my_seq_nr, port, dst_port);

	// start session
	new_session->tlock.lock();

	send_segment(new_session, id, new_session->org_src_addr, new_session->org_src_port, new_session->org_dst_addr, new_session->org_dst_port, 512, FLAG_SYN, new_session->their_seq_nr, &new_session->my_seq_nr, nullptr, 0);

	new_session->tlock.unlock();

	return port;
}

void tcp::close_client_session(const int port)
{
	// lock all sessions
	std::unique_lock<std::mutex> lck(sessions_lock);

	// find id of the session
	auto it_id = tcp_clients.find(port);
	if (it_id == tcp_clients.end())
		return;

	// find session data
	auto sd_it = sessions.find(it_id->second);
	if (sd_it == sessions.end())
		return;

	// send FIN
	sd_it->second->tlock.lock();
	end_session(sd_it->second);
	sd_it->second->tlock.unlock();
}

void tcp::wait_for_client_connected_state(const int local_port)
{
	while(!stop_flag) {
		DOLOG(debug, "wait_for_client_connected_state: lock all sessions\n");

		// lock all sessions
		std::unique_lock<std::mutex> lck(sessions_lock);

		DOLOG(debug, "wait_for_client_connected_state: find session id for %d\n", local_port);

		// find id of the session
		auto it_id = tcp_clients.find(local_port);
		if (it_id == tcp_clients.end()) {
			DOLOG(debug, "wait_for_client_connected_state: session id not found\n");
			return;
		}

		DOLOG(debug, "wait_for_client_connected_state: session id: [%012" PRIx64 "]\n", it_id->second);

		auto sd_it = sessions.find(it_id->second);
		if (sd_it == sessions.end())
			return;

		DOLOG(debug, "wait_for_client_connected_state: found session-data, send_data\n");

		tcp_session_t *const cur_session = sd_it->second;
		int counter = 0;

		if (cur_session->state >= tcp_established) {
			DOLOG(debug, "wait_for_client_connected_state: found session-data, data sent\n");
			break;
		}


		if (time(nullptr) - cur_session->state_since >= 30) {
			end_session(sd_it->second);
			DOLOG(debug, "wait_for_client_connected_state: session setup time-out\n");
			return;
		}

		if (++counter == 3) {
			counter = 0;

			cur_session->tlock.lock();

			send_segment(cur_session, cur_session->id, cur_session->org_src_addr, cur_session->org_src_port, cur_session->org_dst_addr, cur_session->org_dst_port, 512, FLAG_SYN, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0);

			cur_session->tlock.unlock();
		}

		DOLOG(debug, "client waiting for 'established': STATE NOW IS %s\n", states[sd_it->second->state]);

		cur_session->state_changed.wait_for(lck, 500ms);
		// NOTE: after the wait_for, the 'cur_session' pointer may be invalid as
		// lck gets unlocked by the wait_for
	}
}

void tcp::client_session_send_data(const int local_port, const uint8_t *const data, const size_t len)
{
	DOLOG(debug, "client_session_send_data: lock all sessions\n");

	// lock all sessions
	std::unique_lock<std::mutex> lck(sessions_lock);

	DOLOG(debug, "client_session_send_data: find session id for %d\n", local_port);

	// find id of the session
	auto it_id = tcp_clients.find(local_port);
	if (it_id == tcp_clients.end()) {
		DOLOG(debug, "client_session_send_data: session id not found\n");
		return;
	}

	DOLOG(debug, "client_session_send_data: session id: [%012" PRIx64 "]\n", it_id->second);

	auto sd_it = sessions.find(it_id->second);
	if (sd_it == sessions.end())
		return;

	DOLOG(debug, "client_session_send_data: found session-data, send_data\n");

	tcp_session_t *const cur_session = sd_it->second;

	send_data(cur_session, data, len);

	DOLOG(debug, "client_session_send_data: found session-data, data sent\n");
}
