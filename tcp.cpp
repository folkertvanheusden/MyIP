// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <atomic>
#include <chrono>
#include <inttypes.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "icmp.h"
#include "ipv4.h"
#include "log.h"
#include "str.h"
#include "tcp.h"
#include "time.h"
#include "utils.h"


using namespace std::chrono_literals;

constexpr const char *const states[] = { "closed", "listen", "syn_rcvd", "syn_sent", "established", "fin_wait_1", "fin_wait_2", "close_wait", "last_ack", "closing", "time_wait", "rst_act" };

#define FLAG_CWR (1 << 7)
#define FLAG_ECE (1 << 6)
#define FLAG_URG (1 << 5)
#define FLAG_ACK (1 << 4)
#define FLAG_PSH (1 << 3)
#define FLAG_RST (1 << 2)
#define FLAG_SYN (1 << 1)
#define FLAG_FIN (1 << 0)

void tcp::free_tcp_session(tcp_session *const p)
{
	auto port_record = get_lock_listener(p->get_my_port(), -1);

	if (port_record.has_value()) {
		port_record.value().session_closed_1(this, p);

		port_record.value().session_closed_2(this, p);
	}

	release_listener_lock();

	free(p->unacked);

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

tcp::tcp(stats *const s, icmp *const icmp_, const int n_threads) : ip_protocol(s, "tcp"), icmp_(icmp_)
{
	tcp_packets           = s->register_stat("tcp_packets");
	tcp_errors            = s->register_stat("tcp_errors", "1.3.6.1.2.1.6.7");  // tcpAttemptFails
	tcp_succ_estab        = s->register_stat("tcp_succ_estab");
	tcp_internal_err      = s->register_stat("tcp_internal_err");
	tcp_syn               = s->register_stat("tcp_syn");
	tcp_new_sessions      = s->register_stat("tcp_new_sessions");
	tcp_sessions_rem      = s->register_stat("tcp_sessions_rem");
	tcp_sessions_to       = s->register_stat("tcp_sessions_to");
	tcp_sessions_closed_1 = s->register_stat("tcp_sessions_closed1");
	tcp_sessions_closed_2 = s->register_stat("tcp_sessions_closed2");
	tcp_rst               = s->register_stat("tcp_rst");
	tcp_cur_n_sessions    = s->register_stat("tcp_cur_n_sessions");

	for(int i=0; i<n_threads; i++)
		ths.push_back(new std::thread(std::ref(*this)));

	th_cleaner = new std::thread(&tcp::session_cleaner, this);

	th_unacked_sender = new std::thread(&tcp::unacked_sender, this);
}

tcp::~tcp()
{
	stop_flag = true;

	for(auto & th : ths) {
		th->join();

		delete th;
	}

	th_unacked_sender->join();
	delete th_unacked_sender;

	th_cleaner->join();
	delete th_cleaner;

	for(auto & s : sessions)
		free_tcp_session(dynamic_cast<tcp_session *>(s.second));
}

int rel_seqnr(const tcp_session *const ts, const bool mine, const uint32_t nr)
{
	return mine ? nr - ts->initial_my_seq_nr : nr - ts->initial_their_seq_nr;
}

void tcp::send_segment(tcp_session *const ts, const uint64_t session_id, const any_addr & my_addr, const int my_port, const any_addr & peer_addr, const int peer_port, const int org_len, const uint8_t flags, const uint32_t ack_to, uint32_t *const my_seq_nr, const uint8_t *const data, const size_t data_len, const uint32_t TSecr)
{
	char *flag_str = flags_to_str(flags);
	DOLOG(ll_debug, "TCP[%012" PRIx64 "]: Sending segment (flags: %02x (%s)), ack to: %u, my seq: %u, len: %zu)\n", session_id, flags, flag_str, rel_seqnr(ts, false, ack_to), my_seq_nr ? rel_seqnr(ts, true, *my_seq_nr) : -1, data_len);
	free(flag_str);

	if (!idev) {
		DOLOG(ll_debug, "TCP[%012" PRIx64 "]: Dropping packet, no physical device assigned (yet)\n", session_id);
		return;
	}

	size_t temp_len = 20 + 12 + data_len;
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

	temp[12] = 8 << 4; // header len
	temp[13] = flags;

	temp[14] = 255;  // window size
	temp[15] = 255;

	temp[16] = temp[17] = 0; // checksum
	temp[18] = temp[19] = 0; // urgent pointer

	// timestamp option
	temp[20] = 8;  // code for timestamp
	temp[21] = 10;  // length of option
	uint64_t us = get_us();
	temp[22] = us >> 24;
	temp[23] = us >> 16;
	temp[24] = us >>  8;
	temp[25] = us;
	temp[26] = TSecr >> 24;
	temp[27] = TSecr >> 16;
	temp[28] = TSecr >>  8;
	temp[29] = TSecr;

	// padding
	temp[30] = 1;
	temp[31] = 0;

	if (data_len)
		memcpy(&temp[32], data, data_len);

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

	ts->e_last_pkt_ts = get_us();
}

std::optional<port_handler_t> tcp::get_lock_listener(const int dst_port, const uint64_t id)
{
	listeners_lock.lock();

	auto cb_it = listeners.find(dst_port);

	if (cb_it == listeners.end()) {
		DOLOG(ll_info, "TCP[%012" PRIx64 "]: no listener for that (%d) port\n", id, dst_port);

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

void tcp::set_state(tcp_session *const session, const tcp_state_t new_state)
{
	DOLOG(ll_debug, "TCP[%012" PRIx64 "]: changing state from %s to %s\n", session->id, states[session->state], states[new_state]);

	session->state = new_state;
	session->state_since = time(nullptr);

	session->state_changed.notify_all();
}

void tcp::send_rst_for_port(const packet *const pkt, const int dst_port, const int src_port)
{
	if (!idev) {
		DOLOG(ll_debug, "TCP[]: Dropping packet, no physical device assigned (yet)\n");
		return;
	}

	DOLOG(ll_debug, "TCP[]: Sending RST for port %d\n", dst_port);

	size_t   temp_len = 20;
	uint8_t *temp     = new uint8_t[temp_len]();

	temp[0] = dst_port >> 8;
	temp[1] = dst_port & 255;
	temp[2] = src_port >> 8;
	temp[3] = src_port & 255;

	// sequence numbers
	const uint8_t *const p = pkt->get_data();
	memcpy(&temp[4], &p[8], 4);

	uint32_t new_ack_nr = ((p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7]) + 1;
	temp[8]  = new_ack_nr >> 24;
	temp[9]  = new_ack_nr >> 16;
	temp[10] = new_ack_nr >> 8;
	temp[11] = new_ack_nr;

	temp[12] = 5 << 4;  // header length
	temp[13] = FLAG_RST | FLAG_ACK;

	uint16_t checksum = tcp_udp_checksum(pkt->get_src_addr(), pkt->get_dst_addr(), true, temp, temp_len);

	temp[16] = checksum >> 8;
	temp[17] = checksum;

	idev->transmit_packet(pkt->get_src_addr(), pkt->get_dst_addr(), 0x06, temp, temp_len, nullptr);

	delete [] temp;
}

void tcp::packet_handler(const packet *const pkt)
{
	set_thread_name("myip-ptcp-handler");

	const uint8_t *const p    = pkt->get_data();
	const int            size = pkt->get_size();

	if (size < 20) {
		DOLOG(ll_info, "TCP: packet too short [IC]\n");
		delete pkt;
		stats_inc_counter(tcp_errors);
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

	uint32_t their_seq_nr = (p[4] << 24) | (p[5] << 16) | (p[6] << 8)  | p[7];
	uint32_t ack_to       = (p[8] << 24) | (p[9] << 16) | (p[10] << 8) | p[11];

	int header_size = (p[12] >> 4) * 4;

	int win_size    = (p[14] << 8) | p[15];

	auto     src = pkt->get_src_addr();
	uint64_t id  = hash_address(src, dst_port, src_port);

	char    *flag_str = flags_to_str(p[13]);
	DOLOG(ll_debug, "TCP[%012" PRIx64 "]: packet [%s]:%d->[%s]:%d, flags: %02x (%s), their seq: %u, ack to: %u, chksum: 0x%04x, size: %d\n", id, src.to_str().c_str(), src_port, pkt->get_dst_addr().to_str().c_str(), dst_port, p[13], flag_str, their_seq_nr, ack_to, (p[16] << 8) | p[17], size);
	free(flag_str);

	auto port_record  = get_lock_listener(dst_port, id);
	bool has_listener = port_record.has_value();
	release_listener_lock();

	if (!has_listener) {
		send_rst_for_port(pkt, dst_port, src_port);
		delete pkt;
		return;
	}

	std::unique_lock<std::shared_mutex> lck(sessions_lock);

	// check concuncurrent session count
	if (sessions.size() >= 128) {
		DOLOG(ll_debug, "TCP[%012" PRIx64 "]: too many TCP sessions (%zu)\n", id, sessions.size());
		// drop packet
		delete pkt;
		return;
	}

	auto cur_it = sessions.find(id);

	if (cur_it == sessions.end()) {
		if (flag_syn) {  // MUST start with SYN
			private_data *pd          = port_record.value().pd;

			tcp_session  *new_session = new tcp_session(this, pkt->get_dst_addr(), dst_port, pkt->get_src_addr(), src_port, pd);

			new_session->state        = tcp_listen;
			new_session->state_since  = 0;

			get_random((uint8_t *)&new_session->my_seq_nr, sizeof new_session->my_seq_nr);
			new_session->initial_my_seq_nr = new_session->my_seq_nr; // for logging relative(!) sequence numbers

			new_session->initial_their_seq_nr = their_seq_nr;
			new_session->their_seq_nr         = their_seq_nr + 1;

			new_session->id           = id;

			new_session->is_client    = false;

			new_session->unacked      = nullptr;
			new_session->unacked_start_seq_nr    = 0;
			new_session->unacked_size = 0;
			new_session->fin_after_unacked_empty = false;

			new_session->window_size  = win_size;

			sessions.insert({ id, new_session });

			stats_set(tcp_cur_n_sessions, sessions.size());

			stats_inc_counter(tcp_new_sessions);

			DOLOG(ll_debug, "TCP[%012" PRIx64 "]: ...is a new session (initial my seq nr: %u, their: %u)\n", id, new_session->initial_my_seq_nr, new_session->initial_their_seq_nr);

			cur_it = sessions.find(id);
		}
		else {
			lck.unlock();
			DOLOG(ll_debug, "TCP[%012" PRIx64 "]: new session which does not start with SYN [IC]\n", id);
			delete pkt;
			stats_inc_counter(tcp_errors);
			return;
		}
	}

	// process extra headers
	const uint8_t *cur_extra_headers_p = &p[20];
	const uint8_t *const extra_headers_end = &p[header_size];

	uint32_t TSecr = 0;  // TSecr that will be returned if ACK flag is set

	while(extra_headers_end - cur_extra_headers_p >= 2) {
		if (cur_extra_headers_p[0] == 8 && flag_ack) {
			TSecr = (cur_extra_headers_p[2] << 24) | (cur_extra_headers_p[3] << 16) | (cur_extra_headers_p[4] << 8) | cur_extra_headers_p[5];

			DOLOG(ll_debug, "TCP[%012" PRIx64 "]: will set TSecr to %08x\n", TSecr);
		}

		if (cur_extra_headers_p[0] == 0 || cur_extra_headers_p[0] == 1) // 1-byte?
			cur_extra_headers_p++;
		else
			cur_extra_headers_p += cur_extra_headers_p[1];
	}

	tcp_session *const cur_session = dynamic_cast<tcp_session *>(cur_it->second);

	cur_session->e_last_pkt_ts = get_us();

	DOLOG(ll_debug, "TCP[%012" PRIx64 "]: start processing TCP segment, state: %s, my seq nr %d, opponent seq nr %d\n", id, states[cur_session->state], rel_seqnr(cur_session, true, cur_session->my_seq_nr), rel_seqnr(cur_session, false, cur_session->their_seq_nr));
	cur_session->tlock.lock();

	cur_session->window_size = std::max(1, win_size);

	bool fail         = false;
	bool delete_entry = false;

	if (header_size > size) {
		DOLOG(ll_info, "TCP[%012" PRIx64 "]: header with options > packet size [F]\n", id);
		fail = true;
	}

	if (!fail) {
		if (flag_rst) {
			if (cur_session->state >= tcp_syn_rcvd) {
				DOLOG(ll_debug, "TCP[%012" PRIx64 "]: received RST: session setup aborted\n", id);
				set_state(cur_session, tcp_closing);
				delete_entry = true;
			}		
			else {
				DOLOG(ll_debug, "TCP[%012" PRIx64 "]: unexpected RST\n", id);
			}
		}

		if (flag_syn && !delete_entry) {
			stats_inc_counter(tcp_syn);

			// tcp_syn_rcvd: opponent may not have received the syn,ack reply
			if (cur_session->state == tcp_listen || cur_session->state == tcp_syn_rcvd) {
				DOLOG(ll_debug, "TCP[%012" PRIx64 "]: received SYN, send SYN + ACK\n", id);
				// send SYN + ACK
				send_segment(cur_session, id, cur_session->get_my_addr(), cur_session->get_my_port(), cur_session->get_their_addr(), cur_session->get_their_port(), win_size, FLAG_SYN | FLAG_ACK, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0, TSecr);

				set_state(cur_session, tcp_syn_rcvd);
			}
			else if (cur_session->state != tcp_syn_sent) { // not a client?
				DOLOG(ll_debug, "TCP[%012" PRIx64 "]: unexpected SYN\n", id);
			}
		}

		if (flag_ack && !delete_entry) {
			if (cur_session->state == tcp_syn_sent) { // new session from a client
				cur_session->initial_their_seq_nr = their_seq_nr;
				cur_session->their_seq_nr = their_seq_nr + 1;

				DOLOG(ll_debug, "TCP[%012" PRIx64 "]: received ACK%s: session established, their seq: %u, my seq: %u\n", id, flag_syn ? " and SYN" : "", cur_session->their_seq_nr, cur_session->my_seq_nr);

				send_segment(cur_session, cur_session->id, cur_session->get_their_addr(), cur_session->get_their_port(), cur_session->get_my_addr(), cur_session->get_my_port(), win_size, FLAG_ACK, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0, TSecr);

//				cur_session->my_seq_nr += 1;

				set_state(cur_session, tcp_established);
			}
			// listener (server)
			else if (cur_session->state == tcp_syn_rcvd) {
				DOLOG(ll_debug, "TCP[%012" PRIx64 "]: received ACK: session is established\n", id);
				set_state(cur_session, tcp_established);

				stats_inc_counter(tcp_succ_estab);

				auto cb = get_lock_listener(dst_port, id);

				if (cb.has_value()) {
					if (cb.value().new_session && cb.value().new_session(this, cur_session) == false) {
						DOLOG(ll_debug, "TCP[%012" PRIx64 "]: session terminated by layer 7\n", id);
						fail = true;
					}
				}
				else {
					fail = true;
				}

				release_listener_lock();
			}
			else if (cur_session->state == tcp_last_ack) {
				DOLOG(ll_debug, "TCP[%012" PRIx64 "]: received ACK: session is finished\n", id);
				set_state(cur_session, tcp_listen);  // tcp_closed really
				delete_entry = true;
			}
			// opponent acknowledges the reception of a bit of data
			else if (cur_session->state == tcp_established) {
				int ack_n = ack_to - cur_session->unacked_start_seq_nr;

				if (ack_n > 0 && cur_session->unacked_size > 0) {
					DOLOG(ll_debug, "TCP[%012" PRIx64 "]: ack to: %u (last seq nr %u), size: %d), unacked currently: %zu\n", id, rel_seqnr(cur_session, true, ack_to), rel_seqnr(cur_session, true, cur_session->my_seq_nr), ack_n, cur_session->unacked_size);

					// delete acked
					int left_n = cur_session->unacked_size - ack_n;
					if (left_n > 0)
						memmove(&cur_session->unacked[0], &cur_session->unacked[ack_n], left_n);
					else if (left_n < 0) {
						DOLOG(ll_warning, "TCP[%012" PRIx64 "]: ack underrun? %d\n", id, left_n);
						// terminate this invalid session
						// can happen for data coming in after finished
						delete_entry = fail = true;
					}

					cur_session->unacked_size -= ack_n;
					cur_session->unacked_start_seq_nr += ack_n;

					DOLOG(ll_debug, "TCP[%012" PRIx64 "]: unacked left: %zu, fin after empty: %d\n", id, cur_session->unacked_size, cur_session->fin_after_unacked_empty);

					cur_session->my_seq_nr += ack_n;

					if (cur_session->unacked_size == 0 && cur_session->fin_after_unacked_empty) {
						DOLOG(ll_debug, "TCP[%012" PRIx64 "]: unacked buffer empy, FIN\n", id);

						send_segment(cur_session, cur_session->id, cur_session->get_my_addr(), cur_session->get_my_port(), cur_session->get_their_addr(), cur_session->get_their_port(), win_size, FLAG_ACK | FLAG_FIN /* ACK, FIN */, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0, TSecr);

						set_state(cur_session, tcp_fin_wait_1);
					}

					if (cur_session->unacked_size > 0)
						cur_session->r_last_pkt_ts = cur_session->e_last_pkt_ts;
				}

				unacked_cv.notify_all();
			}
			else {
				DOLOG(ll_debug, "TCP[%012" PRIx64 "]: unexpected ACK\n", id);
			}

			cur_session->data_since_last_ack = 0;
		}

		if (flag_fin) {
			if (cur_session->state == tcp_established) {
				DOLOG(ll_debug, "TCP[%012" PRIx64 "]: received FIN\n", id);

				DOLOG(ll_debug, "TCP[%012" PRIx64 "]: cur_session->their_seq_nr %ld, their: %ld\n", id, cur_session->their_seq_nr, their_seq_nr);

				cur_session->seq_for_fin_when_all_received = their_seq_nr;
				cur_session->flag_fin_when_all_received    = true;

				cur_session->set_is_terminating();

				set_state(cur_session, tcp_fin_wait_1);
			}
			else {
				DOLOG(ll_debug, "TCP[%012" PRIx64 "]: unexpected FIN\n", id);
			}
		}

		if (cur_session->flag_fin_when_all_received && cur_session->seq_for_fin_when_all_received == cur_session->their_seq_nr) {
			DOLOG(ll_debug, "TCP[%012" PRIx64 "]: ack FIN after all data has been received\n", id);

			// send ACK + FIN
			if (cur_session->is_client)
				send_segment(cur_session, id, cur_session->get_their_addr(), cur_session->get_their_port(), cur_session->get_my_addr(), cur_session->get_my_port(), win_size, FLAG_ACK | FLAG_FIN, cur_session->their_seq_nr + 1, &cur_session->my_seq_nr, nullptr, 0, TSecr);
			else
				send_segment(cur_session, id, cur_session->get_my_addr(), cur_session->get_my_port(), cur_session->get_their_addr(), cur_session->get_their_port(), win_size, FLAG_ACK | FLAG_FIN, cur_session->their_seq_nr + 1, &cur_session->my_seq_nr, nullptr, 0, TSecr);

			set_state(cur_session, tcp_fin_wait_2);

			delete_entry = true;
		}
	}

	// process payload
	int data_len = size - header_size;
	if (data_len > 0 && fail == false) {
		DOLOG(ll_debug, "TCP[%012" PRIx64 "]: packet len %d, header size: %d, payload size: %d\n", id, size, header_size, data_len);

		const uint8_t *data_start = &p[header_size];

		// DOLOG(ll_debug, "TCP[%012" PRIx64 "]: %s\n", id, std::string((const char *)&p[header_size], data_len).c_str());

		if (their_seq_nr == cur_session->their_seq_nr) {
			// std::string content = bin_to_text(data_start, data_len);
			// DOLOG(ll_debug, "TCP[%012" PRIx64 "]: Received content: %s\n", id, content.c_str());

			auto cb = get_lock_listener(dst_port, id);

			if (cb.has_value()) {
				if (cb.value().new_data(this, cur_session, buffer_in(data_start, data_len)) == false) {
					DOLOG(ll_error, "TCP[%012" PRIx64 "]: layer 7 indicated an error\n", id);
					fail = true;
				}
			}
			else {
				fail = true;
			}

			release_listener_lock();

			if (fail == false) {
				cur_session->their_seq_nr += data_len;  // TODO handle missing segments

				for(;;) {
					auto it = cur_session->fragments.find(cur_session->their_seq_nr);
					if (it == cur_session->fragments.end())
						break;

					DOLOG(ll_debug, "TCP[%012" PRIx64 "]: use from fragment cache\n", id);

					auto cb = get_lock_listener(dst_port, id);

					if (cb.value().new_data(this, cur_session, buffer_in(it->second.data(), it->second.size())) == false) {
						DOLOG(ll_error, "TCP[%012" PRIx64 "]: layer 7 indicated an error\n", id);
						fail = true;
					}

					release_listener_lock();

					cur_session->their_seq_nr += it->second.size();

					cur_session->fragments.erase(it);

					if (fail)
						break;
				}
			}

			if (fail == false) {
				// will be acked in the 'unacked_sender'-thread
				if (cur_session->unacked_size == 0) {
					DOLOG(ll_debug, "TCP[%012" PRIx64 "]: acknowledging received content\n", id);

					if (cur_session->is_client)
						send_segment(cur_session, id, cur_session->get_their_addr(), cur_session->get_their_port(), cur_session->get_my_addr(), cur_session->get_my_port(), win_size, FLAG_ACK, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0, TSecr);
					else
						send_segment(cur_session, id, cur_session->get_my_addr(), cur_session->get_my_port(), cur_session->get_their_addr(), cur_session->get_their_port(), win_size, FLAG_ACK, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0, TSecr);
				}
			}
		}
		else {
			DOLOG(ll_info, "TCP[%012" PRIx64 "]: unexpected sequence nr %u, expected: %u\n", id, rel_seqnr(cur_session, false, their_seq_nr), rel_seqnr(cur_session, false, cur_session->their_seq_nr));

			if (their_seq_nr > cur_session->their_seq_nr) {
				std::vector<uint8_t> fragment(data_start, data_start + data_len);

				cur_session->fragments.insert({ their_seq_nr, std::move(fragment) });

				DOLOG(ll_info, "TCP[%012" PRIx64 "]: number of fragments in cache: %zu\n", id, cur_session->fragments.size());
			}

			const uint32_t ack_to = cur_session->their_seq_nr;

			if (cur_session->is_client)
				send_segment(cur_session, id, cur_session->get_their_addr(), cur_session->get_their_port(), cur_session->get_my_addr(), cur_session->get_my_port(), win_size, FLAG_ACK, ack_to, &cur_session->my_seq_nr, nullptr, 0, TSecr);
			else
				send_segment(cur_session, id, cur_session->get_my_addr(), cur_session->get_my_port(), cur_session->get_their_addr(), cur_session->get_their_port(), win_size, FLAG_ACK, ack_to, &cur_session->my_seq_nr, nullptr, 0, TSecr);
		}

		unacked_cv.notify_all();
	}

	if (fail) {
		auto cb = get_lock_listener(dst_port, id);

		if (cb.has_value())
			cb.value().session_closed_1(this, cur_session);

		release_listener_lock();

		stats_inc_counter(tcp_errors);

		cur_session->unacked_sent_cv.notify_all();

		delete_entry = true;

		DOLOG(ll_info, "TCP[%012" PRIx64 "]: sending fail packet [IC]\n", id);
		if (cur_session->is_client)
			send_segment(cur_session, id, cur_session->get_their_addr(), cur_session->get_their_port(), cur_session->get_my_addr(), cur_session->get_my_port(), win_size, FLAG_RST | FLAG_ACK, their_seq_nr + 1, nullptr, nullptr, 0, TSecr);
		else
			send_segment(cur_session, id, cur_session->get_my_addr(), cur_session->get_my_port(), cur_session->get_their_addr(), cur_session->get_their_port(), win_size, FLAG_RST | FLAG_ACK, their_seq_nr + 1, nullptr, nullptr, 0, TSecr);
	}

	if (delete_entry)
		cur_session->set_is_terminating();

	cur_session->tlock.unlock();

	lck.unlock();

	if (delete_entry) {
		DOLOG(ll_info, "TCP[%012" PRIx64 "]: cleaning up session\n", id);

		lck.lock();

		cur_it = sessions.find(id);

		if (cur_it != sessions.end()) {
			tcp_session *pointer = dynamic_cast<tcp_session *>(cur_it->second);

			sessions.erase(cur_it);
			stats_set(tcp_cur_n_sessions, sessions.size());

			lck.unlock();

			bool is_client       = pointer->is_client;

			// call session_closed_2
			int close_port       = is_client ? pointer->get_their_port() : pointer->get_my_port();

			auto cb_org          = get_lock_listener(close_port, id);

			if (cb_org.has_value())  // is session initiated here?
				cb_org.value().session_closed_2(this, pointer);
			else
				DOLOG(ll_info, "TCP[%012" PRIx64 "]: port %d not known\n", id, close_port);

			release_listener_lock();

			// clean-up
			free_tcp_session(pointer);
		}
		else {
			lck.unlock();
		}

		stats_inc_counter(tcp_sessions_rem);
	}

	delete pkt;
}

void tcp::session_cleaner()
{
	set_thread_name("myip-tcp-clnr");

	while(!stop_flag) {
		using namespace std::chrono_literals;

		// TODO: langere wachttijd en wakker maken elders als state != established gezet wordt
		std::unique_lock<std::shared_mutex> lck(sessions_lock);
		if (sessions_cv.wait_for(lck, 1s) == std::cv_status::no_timeout)
			DOLOG(ll_debug, "tcp-clnr woke-up after ack\n");

		// find t/o'd sessions
		uint64_t now = get_us();

		for(auto it = sessions.cbegin(); it != sessions.cend();) {
			tcp_session *const s = dynamic_cast<tcp_session *>(it->second);

			uint64_t age = (now - s->e_last_pkt_ts) / 1000000;

			if (age >= session_timeout || s->state > tcp_established) {
				if (s->state > tcp_established)
					DOLOG(ll_debug, "TCP[%012" PRIx64 "]: session closed (state: %s)\n", it->first, states[s->state]);
				else
					DOLOG(ll_debug, "TCP[%012" PRIx64 "]: session timed out\n", it->first);

				// call session_closed
				auto cb = get_lock_listener(s->get_my_port(), it->first);

				if (cb.has_value()) {  // session not initiated here?
					cb.value().session_closed_1(this, s);
					cb.value().session_closed_2(this, s);
				}

				release_listener_lock();

				// clean-up
				free_tcp_session(s);

				it = sessions.erase(it);

				stats_inc_counter(tcp_sessions_to);
			}
			else if (s->state == tcp_time_wait && age >= 2) {
				DOLOG(ll_debug, "TCP[%012" PRIx64 "]: session clean-up after tcp_time_wait state\n", it->first);

				if (s->is_client) {
					// forget client session
					tcp_clients.erase(s->get_their_port());
				}

				// clean-up
				free_tcp_session(s);

				it = sessions.erase(it);
			}
			else if (s->state == tcp_syn_rcvd && age >= 5) {
				DOLOG(ll_debug, "TCP[%012" PRIx64 "]: delete session in SYN state for 5 or more seconds\n", it->first);

				if (s->is_client)
					tcp_clients.erase(s->get_their_port());

				free_tcp_session(s);

				it = sessions.erase(it);
			}
			else {
				++it;
			}
		}

		stats_set(tcp_cur_n_sessions, sessions.size());

		lck.unlock();
	}
}

void tcp::unacked_sender()
{
	set_thread_name("myip-tcp-us");

	while(!stop_flag) {
		using namespace std::chrono_literals;

		std::unique_lock<std::shared_mutex> lck(sessions_lock);
		if (unacked_cv.wait_for(lck, 1s) == std::cv_status::no_timeout)
			DOLOG(ll_debug, "TCP[] unack woke-up after ack\n");

		// go through all sessions and find if any has segments to resend
		uint64_t now = get_us();

		for(auto it = sessions.cbegin(); it != sessions.cend(); it++) {
			tcp_session *const s = dynamic_cast<tcp_session *>(it->second);

			// last packet >= 1s ago?
			if (now - s->r_last_pkt_ts >= 1000000) {
				s->tlock.lock();

				bool notify = false;

				int to_send = std::min(s->window_size - s->data_since_last_ack, s->unacked_size);
				int packet_size = idev->get_max_packet_size() - (20 + 12 /* timestamp option + padding */);

				uint32_t resend_nr = s->my_seq_nr;

				for(int i=0; i<to_send; i += packet_size) {
					size_t send_n = std::min(packet_size, to_send - i);

					DOLOG(ll_debug, "TCP[%012" PRIx64 "]: unack SEND %zu bytes for sequence nr %u (win size: %d, unacked: %zu, data since ack: %ld)\n", it->first, send_n, rel_seqnr(s, true, s->my_seq_nr), s->window_size, s->unacked_size, s->data_since_last_ack);

					if (s->is_client)
						send_segment(s, s->id, s->get_their_addr(), s->get_their_port(), s->get_my_addr(), s->get_my_port(), 0, FLAG_ACK, s->their_seq_nr, &resend_nr, &s->unacked[i], send_n, 0);
					else
						send_segment(s, s->id, s->get_my_addr(), s->get_my_port(), s->get_their_addr(), s->get_their_port(), 0, FLAG_ACK, s->their_seq_nr, &resend_nr, &s->unacked[i], send_n, 0);

					s->data_since_last_ack += send_n;

					notify = true;
				}

				s->tlock.unlock();

				if (notify)
					s->unacked_sent_cv.notify_one();

				s->r_last_pkt_ts = 0;
			}
		}

		lck.unlock();
	}
}

// process incoming packets
void tcp::operator()()
{
	set_thread_name("myip-tcp");

	while(!stop_flag) {
		auto po = pkts->get(500);
		if (!po.has_value())
			continue;

		const packet *pkt = po.value();

		stats_inc_counter(tcp_packets);

		packet_handler(pkt);

		sessions_cv.notify_all();
	}
}

void tcp::add_handler(const int port, port_handler_t & tph)
{
	if (tph.init)
		tph.init();

	listeners_lock.lock();

	listeners.insert({ port, tph });

	listeners_lock.unlock();
}

bool tcp::send_data(session *const ts_in, const uint8_t *const data, const size_t len)
{
	uint64_t internal_id = get_us();

	tcp_session *const ts = dynamic_cast<tcp_session *>(ts_in);

	DOLOG(ll_debug, "TCP[%012" PRIx64 "]: send frame, %zu bytes, internal id: %lu, %lu packets\n", ts->id, len, internal_id, (len + ts->window_size - 1) / ts->window_size);
	DOLOG(ll_debug, "TCP[%012" PRIx64 "]: %s\n", ts->id, std::string((const char *)data, len).c_str());

	for(;;) {
		// lock for unacked and for my_seq_nr
		std::unique_lock<std::mutex> lck(ts->tlock);

		if (ts->unacked_size < 1024 * 1024)  // max 1MB queued
			break;

		if (ts->state != tcp_established || ts->get_is_terminating()) {
			DOLOG(ll_debug, "TCP[%012" PRIx64 "]: send_data interrupted by session end\n", ts->id);
			break;
		}

		ts->unacked_sent_cv.wait_for(lck, 100ms);

		DOLOG(ll_debug, "TCP[%012" PRIx64 "]: unacked-buffer full\n", ts->id);
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

	return true;
}

// this method requires tcp_session to be already locked
void tcp::end_session(session *const ts_in)
{
	tcp_session *const ts = dynamic_cast<tcp_session *>(ts_in);

	if (ts->unacked_size == 0) {
		DOLOG(ll_debug, "TCP[%012" PRIx64 "]: end session, seq %u\n", ts->id, rel_seqnr(ts, true, ts->my_seq_nr));

		if (ts->is_client)
			send_segment(ts, ts->id, ts->get_their_addr(), ts->get_their_port(), ts->get_my_addr(), ts->get_my_port(), 1, FLAG_FIN, ts->their_seq_nr, &ts->my_seq_nr, nullptr, 0, 0);
		else
			send_segment(ts, ts->id, ts->get_my_addr(), ts->get_my_port(), ts->get_their_addr(), ts->get_their_port(), 1, FLAG_FIN, ts->their_seq_nr, &ts->my_seq_nr, nullptr, 0, 0);

		set_state(ts, tcp_fin_wait_1);
	}
	else {
		DOLOG(ll_debug, "TCP[%012" PRIx64 "]: schedule end session, after %ld bytes\n", ts->id, ts->unacked_size);

		ts->fin_after_unacked_empty = true;
	}
}

int tcp::allocate_client_session(const std::function<bool(pstream *const ps, session *const s, buffer_in data)> & new_data, const std::function<bool(pstream *const ps, session *const s)> & session_closed_2, const any_addr & dst_addr, const int dst_port, session_data *const sd)
{
	port_handler_t handler { 0 };
	handler.new_data         = new_data;
	handler.pd               = nullptr;
	handler.session_closed_2 = session_closed_2;

	// generate id/port mapping
	uint16_t port = 0;

	// lock all sesions
	std::unique_lock<std::shared_mutex> lck(sessions_lock);

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
	tcp_session *new_session = new tcp_session(this, dst_addr, dst_port, src, port, nullptr);
	new_session->state       = tcp_syn_sent;
	new_session->state_since = time(nullptr);

	new_session->is_client   = true;

	get_random((uint8_t *)&new_session->my_seq_nr, sizeof new_session->my_seq_nr);
	new_session->initial_my_seq_nr = new_session->my_seq_nr; // for logging relative(!) sequence numbers

	new_session->initial_their_seq_nr = 0;
	new_session->their_seq_nr         = 0;

	new_session->id = id;

	new_session->unacked                 = nullptr;
	new_session->unacked_start_seq_nr    = 0;
	new_session->unacked_size            = 0;
	new_session->fin_after_unacked_empty = false;

	new_session->seq_for_fin_when_all_received = 0;

	new_session->window_size = idev->get_max_packet_size();

	new_session->set_callback_private_data(sd);

	stats_inc_counter(tcp_new_sessions);

	// connect id to session data
	sessions.insert({ id, new_session });
	stats_set(tcp_cur_n_sessions, sessions.size());

	add_handler(port, handler);

	lck.unlock();

	DOLOG(ll_debug, "TCP[%012" PRIx64 "]: new client session, my seq nr: %u, local port: %d, destination port: %d\n", id, new_session->initial_my_seq_nr, port, dst_port);

	// start session
	new_session->tlock.lock();

	send_segment(new_session, id, new_session->get_their_addr(), new_session->get_their_port(), new_session->get_my_addr(), new_session->get_my_port(), 512, FLAG_SYN, new_session->their_seq_nr, &new_session->my_seq_nr, nullptr, 0, 0);

	new_session->tlock.unlock();

	return port;
}

void tcp::close_client_session(const int port)
{
	// lock all sessions
	std::unique_lock<std::shared_mutex> lck(sessions_lock);

	// find id of the session
	auto it_id = tcp_clients.find(port);
	if (it_id == tcp_clients.end())
		return;

	// find session data
	auto sd_it = sessions.find(it_id->second);
	if (sd_it == sessions.end())
		return;

	// send FIN
	tcp_session *const s = dynamic_cast<tcp_session *>(sd_it->second);

	s->tlock.lock();
	end_session(s);
	s->tlock.unlock();
}

void tcp::wait_for_client_connected_state(const int local_port)
{
	int counter = 0;

	while(!stop_flag) {
		DOLOG(ll_debug, "wait_for_client_connected_state: lock all sessions\n");

		// lock all sessions
		std::unique_lock<std::shared_mutex> lck(sessions_lock);

		DOLOG(ll_debug, "wait_for_client_connected_state: find session id for %d\n", local_port);

		// find id of the session
		auto it_id = tcp_clients.find(local_port);
		if (it_id == tcp_clients.end()) {
			DOLOG(ll_debug, "wait_for_client_connected_state: session id not found\n");
			return;
		}

		DOLOG(ll_debug, "wait_for_client_connected_state: session id: [%012" PRIx64 "]\n", it_id->second);

		auto sd_it = sessions.find(it_id->second);
		if (sd_it == sessions.end())
			return;

		DOLOG(ll_debug, "wait_for_client_connected_state: found session-data, send_data\n");

		tcp_session *const cur_session = dynamic_cast<tcp_session *>(sd_it->second);

		if (cur_session->state >= tcp_established) {
			DOLOG(ll_debug, "wait_for_client_connected_state: found session-data, data sent\n");
			break;
		}


		if (time(nullptr) - cur_session->state_since >= 30) {
			end_session(sd_it->second);
			DOLOG(ll_debug, "wait_for_client_connected_state: session setup time-out\n");
			return;
		}

		if (++counter == 3) {
			counter = 0;

			cur_session->tlock.lock();

			send_segment(cur_session, cur_session->id, cur_session->get_their_addr(), cur_session->get_their_port(), cur_session->get_my_addr(), cur_session->get_my_port(), 512, FLAG_SYN, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0, 0);

			cur_session->tlock.unlock();
		}

		DOLOG(ll_debug, "client waiting for 'established': STATE NOW IS %s\n", states[cur_session->state]);

		cur_session->state_changed.wait_for(lck, 500ms);
		// NOTE: after the wait_for, the 'cur_session' pointer may be invalid as
		// lck gets unlocked by the wait_for
	}
}

void tcp::client_session_send_data(const int local_port, const uint8_t *const data, const size_t len)
{
	DOLOG(ll_debug, "client_session_send_data: lock all sessions\n");

	// lock all sessions
	std::unique_lock<std::shared_mutex> lck(sessions_lock);

	DOLOG(ll_debug, "client_session_send_data: find session id for %d\n", local_port);

	// find id of the session
	auto it_id = tcp_clients.find(local_port);
	if (it_id == tcp_clients.end()) {
		DOLOG(ll_debug, "client_session_send_data: session id not found\n");
		return;
	}

	DOLOG(ll_debug, "client_session_send_data: session id: [%012" PRIx64 "]\n", it_id->second);

	auto sd_it = sessions.find(it_id->second);
	if (sd_it == sessions.end())
		return;

	DOLOG(ll_debug, "client_session_send_data: found session-data, send_data\n");

	tcp_session *const cur_session = dynamic_cast<tcp_session *>(sd_it->second);

	send_data(cur_session, data, len);

	DOLOG(ll_debug, "client_session_send_data: found session-data, data sent\n");
}
