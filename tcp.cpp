// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
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

tcp::tcp(stats *const s)
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

	th = new std::thread(std::ref(*this));
}

tcp::~tcp()
{
	for(auto p : pkts)
		delete p;

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
	dolog(debug, "TCP[%012" PRIx64 "]: Sending segment (flags: %02x (%s)), ack to: %u, my seq: %u, len: %zu)\n", session_id, flags, flag_str, rel_seqnr(ts, false, ack_to), my_seq_nr ? rel_seqnr(ts, true, *my_seq_nr) : -1, data_len);
	free(flag_str);

	if (!idev) {
		dolog(debug, "TCP[%012" PRIx64 "]: Dropping packet, no physical device assigned (yet)\n", session_id);
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

void tcp::packet_handler(const packet *const pkt, std::atomic_bool *const finished_flag)
{
	set_thread_name("myip-pkt-handler");

	const uint8_t *const p = pkt->get_data();
	const int size = pkt->get_size();

	if (size < 20) {
		dolog(info, "TCP: packet too short\n");
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

	auto cb_it = listeners.find(dst_port);

	auto src = pkt->get_src_addr();
	uint64_t id = src.get_hash() ^ (uint64_t(src_port) << 31);

	char *flag_str = flags_to_str(p[13]);
	dolog(debug, "TCP[%012" PRIx64 "]: packet [%s]:%d->[%s]:%d, flags: %02x (%s), their seq: %u, ack to: %u, chksum: 0x%04x, size: %d\n", id, src.to_str().c_str(), src_port, pkt->get_dst_addr().to_str().c_str(), dst_port, p[13], flag_str, their_seq_nr, ack_to, (p[16] << 8) | p[17], size);
	free(flag_str);

	sessions_lock.lock();

	auto cur_it = sessions.find(id);

	if (cur_it == sessions.end()) {
		if (flag_syn) {  // MUST start with SYN
			tcp_session_t *new_session = new tcp_session_t();
			new_session->state = tcp_listen;

			get_random((uint8_t *)&new_session->my_seq_nr, sizeof new_session->my_seq_nr);
			new_session->initial_my_seq_nr = new_session->my_seq_nr; // for logging relative(!) sequence numbers

			new_session->initial_their_seq_nr = their_seq_nr;
			new_session->their_seq_nr = their_seq_nr + 1;

			new_session->id = id;

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

			stats_inc_counter(tcp_new_sessions);

			dolog(debug, "TCP[%012" PRIx64 "]: ...is a new session (initial my seq nr: %u, their: %u)\n", id, new_session->initial_my_seq_nr, new_session->initial_their_seq_nr);

			cur_it = sessions.find(id);
		}
		else {
			sessions_lock.unlock();
			dolog(info, "TCP: new session which does not start with SYN\n");
			delete pkt;
			stats_inc_counter(tcp_errors);
			*finished_flag = true;
			return;
		}
	}

	tcp_session_t *const cur_session = cur_it->second;

	cur_session->last_pkt = get_us();

	dolog(debug, "TCP[%012" PRIx64 "]: start processing TCP segment, state: %s, my seq nr %d, opponent seq nr %d\n", id, states[cur_session->state], rel_seqnr(cur_session, true, cur_session->my_seq_nr), rel_seqnr(cur_session, false, cur_session->their_seq_nr));
	cur_session->tlock.lock();

	cur_it->second->window_size = std::max(1, win_size);

	bool fail = false;
	bool delete_entry = false;

	if (header_size > size) {
		dolog(info, "TCP[%012" PRIx64 "]: header with options > packet size\n", id);
		fail = true;
	}

	if (cb_it == listeners.end()) {
		dolog(info, "TCP[%012" PRIx64 "]: no listener for that port\n", id);
		fail = true;
	}

	if (!fail) {
		if (flag_syn) {
			stats_inc_counter(tcp_syn);

			// tcp_syn_rcvd: opponent may not have received the syn,ack reply
			if (cur_session->state == tcp_listen || cur_session->state == tcp_syn_rcvd) {
				dolog(debug, "TCP[%012" PRIx64 "]: received SYN, send SYN + ACK\n", id);
				// send SYN + ACK
				send_segment(cur_session, id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, FLAG_SYN | FLAG_ACK, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0);

				cur_session->state = tcp_syn_rcvd;
			}
			else {
				dolog(debug, "TCP[%012" PRIx64 "]: unexpected SYN\n", id);
			}
		}

		if (flag_ack) {
			if (cur_session->state == tcp_syn_rcvd) {
				dolog(debug, "TCP[%012" PRIx64 "]: received ACK: session is established\n", id);
				cur_session->state = tcp_established;

                                stats_inc_counter(tcp_succ_estab);

                                if (cb_it->second.new_session(cur_session, pkt, cb_it->second.pd) == false) {
                                        dolog(debug, "TCP[%012" PRIx64 "]: session terminated by layer 7\n", id);
                                        fail = true;
                                }
			}
			else if (cur_session->state == tcp_last_ack) {
				dolog(debug, "TCP[%012" PRIx64 "]: received ACK: session is finished\n", id);
				cur_session->state = tcp_listen;  // tcp_closed really
				delete_entry = true;
			}
			// opponent acknowledges the reception of a bit of data
			else if (cur_session->state == tcp_established) {
				int ack_n = ack_to - cur_session->unacked_start_seq_nr;

				if (ack_n > 0 && cur_session->unacked_size > 0) {
					dolog(debug, "TCP[%012" PRIx64 "]: ack to: %u (last seq nr %u), size: %d), unacked currently: %zu\n", id, rel_seqnr(cur_session, true, ack_to), rel_seqnr(cur_session, true, cur_session->my_seq_nr), ack_n, cur_session->unacked_size);

					// delete acked
					int left_n = cur_session->unacked_size - ack_n;
					if (left_n > 0)
						memmove(&cur_session->unacked[0], &cur_session->unacked[ack_n], left_n);
					else if (left_n < 0) {
						dolog(warning, "TCP[%012" PRIx64 "]: ack underrun? %d\n", id, left_n);
						// terminate this invalid session
						// can happen for data coming in after finished
						delete_entry = fail = true;
					}

					cur_session->unacked_size -= ack_n;
					cur_session->unacked_start_seq_nr += ack_n;

					dolog(debug, "TCP[%012" PRIx64 "]: unacked left: %zu, fin after empty: %d\n", id, cur_session->unacked_size, cur_session->fin_after_unacked_empty);

					cur_session->my_seq_nr += ack_n;

					if (cur_session->unacked_size == 0 && cur_session->fin_after_unacked_empty) {
						dolog(debug, "TCP[%012" PRIx64 "]: unacked buffer empy, FIN\n", id);

						send_segment(cur_session, cur_session->id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, (1 << 4) | (1 << 0) /* ACK, FIN */, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0);

						cur_session->state = tcp_fin_wait_1;
					}
				}

				unacked_cv.notify_all();
			}
			else {
				dolog(debug, "TCP[%012" PRIx64 "]: unexpected ACK\n", id);
			}

			cur_session->data_since_last_ack = 0;
		}

		if (flag_rst) {
			if (cur_session->state == tcp_syn_rcvd) {
				dolog(debug, "TCP[%012" PRIx64 "]: received RST: session setup aborted\n", id);
				cur_session->state = tcp_listen;
				delete_entry = true;
			}		
			else {
				dolog(debug, "TCP[%012" PRIx64 "]: unexpected RST\n", id);
			}
		}

		if (flag_fin) {
			if (cur_session->state == tcp_established) {
				dolog(debug, "TCP[%012" PRIx64 "]: received FIN: send ACK + FIN\n", id);
				cur_session->state = tcp_close_wait;
				// send ACK + FIN
				cur_session->their_seq_nr++;
				send_segment(cur_session, id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, FLAG_ACK | FLAG_FIN, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0);

				cur_session->state = tcp_last_ack;
			}
			else {
				dolog(debug, "TCP[%012" PRIx64 "]: unexpected FIN\n", id);
			}
		}
	}

	// process payload
        int data_len = size - header_size;
        if (data_len > 0 && fail == false) {
                dolog(debug, "TCP[%012" PRIx64 "]: packet len %d, header size: %d, payload size: %d\n", id, size, header_size, data_len);

                if (their_seq_nr == cur_session->their_seq_nr) {
                        const uint8_t *data_start = &p[header_size];

                        std::string content = bin_to_text(data_start, data_len);
                        dolog(debug, "TCP[%012" PRIx64 "]: Received content: %s\n", id, content.c_str());

                        try {
                                if (cb_it->second.new_data(cur_session, pkt, data_start, data_len, cb_it->second.pd) == false) {
					dolog(error, "TCP[%012" PRIx64 "]: layer 7 indicated an error\n", id);
                                        fail = true;
				}
                        }
                        catch(...) {
                                dolog(error, "TCP[%012" PRIx64 "]: EXCEPTION IN new_data()\n", id);
                                fail = true;
                        }

			if (fail == false) {
                                cur_session->their_seq_nr += data_len;  // TODO handle missing segments

				// well be acked in the 'unacked_sender'-thread
				if (cur_session->unacked_size == 0) {
					dolog(debug, "TCP[%012" PRIx64 "]: acknowledging received content\n", id);

					send_segment(cur_session, id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, (1 << 4) /* ACK */, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0);
				}
                        }
                }
                else {
                        dolog(info, "TCP[%012" PRIx64 "]: unexpected sequence nr %u, expected: %u\n", id, rel_seqnr(cur_session, false, their_seq_nr), rel_seqnr(cur_session, false, cur_session->their_seq_nr));

			if (cur_session->unacked_size == 0) {
				dolog(debug, "TCP[%012" PRIx64 "]: re-acknowledging received content to trigger resend\n", id);

				send_segment(cur_session, id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, (1 << 4) /* ACK */, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0);
			}
                }

                unacked_cv.notify_all();
        }

        if (fail) {
                if (cb_it != listeners.end())
                        cb_it->second.session_closed_1(cur_session, cb_it->second.pd);

                stats_inc_counter(tcp_errors);

		cur_session->unacked_sent_cv.notify_all();

                delete_entry = true;

                dolog(info, "TCP[%012" PRIx64 "]: sending fail packet\n", id);
                send_segment(cur_session, id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, (1 << 2) | (1 << 4) /* RST, ACK */, their_seq_nr + 1, nullptr, nullptr, 0);
        }

	cur_session->tlock.unlock();

	sessions_lock.unlock();

	if (delete_entry) {
		dolog(info, "TCP[%012" PRIx64 "]: cleaning up session\n", id);

		sessions_lock.lock();

		cur_it = sessions.find(id);

		if (cur_it != sessions.end()) {
			tcp_session_t *pointer = cur_it->second;
			sessions.erase(cur_it);
			sessions_lock.unlock();

			// call session_closed_2
			auto cb_org_it = listeners.find(pointer->org_dst_port);

			if (cb_org_it != listeners.end())  // session not initiated here?
				cb_org_it->second.session_closed_2(pointer, cb_org_it->second.pd);

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
			dolog(debug, "tcp-clnr woke-up after ack\n");

		// find t/o'd sessions
		uint64_t now = get_us();

		for(auto it = sessions.cbegin(); it != sessions.cend();) {
			uint64_t age = (now - it->second->last_pkt) / 1000000;

			if (age >= session_timeout || it->second->state > tcp_established) {
				if (it->second->state > tcp_established)
					dolog(debug, "TCP[%012" PRIx64 "]: session closed (state: %s)\n", it->first, states[it->second->state]);
				else
					dolog(debug, "TCP[%012" PRIx64 "]: session timed out\n", it->first);

				// call session_closed
				auto cb_it = listeners.find(it->second->org_dst_port);

				if (cb_it != listeners.end()) {  // session not initiated here?
					cb_it->second.session_closed_1(it->second, cb_it->second.pd);
					cb_it->second.session_closed_2(it->second, cb_it->second.pd);
				}

				// clean-up
				free_tcp_session(it->second);

				it = sessions.erase(it);

				stats_inc_counter(tcp_sessions_to);
			}
			else if (it->second->state == tcp_time_wait && age >= 2) {
				dolog(debug, "TCP[%012" PRIx64 "]: session clean-up after tcp_time_wait state\n", it->first);

				// clean-up
				free_tcp_session(it->second);

				it = sessions.erase(it);
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
			dolog(debug, "tcp-unack woke-up after ack\n");

		// go through all sessions and find if any has segments to resend

		for(auto it = sessions.cbegin(); it != sessions.cend(); it++) {
			it->second->tlock.lock();

			bool notify = false;

			int to_send = std::min(it->second->window_size - it->second->data_since_last_ack, it->second->unacked_size);
			int packet_size = idev->get_max_packet_size() - 20;

			uint32_t resend_nr = it->second->my_seq_nr;

			for(int i=0; i<to_send; i += packet_size) {
				size_t send_n = std::min(packet_size, to_send - i);

				dolog(debug, "tcp-unack SEND %zu bytes for sequence nr %u (win size: %d, unacked: %zu, data since ack: %d)\n", send_n, rel_seqnr(it->second, true, it->second->my_seq_nr), it->second->window_size, it->second->unacked_size, it->second->data_since_last_ack);

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
		std::unique_lock<std::mutex> lck(pkts_lock);

		while(pkts.empty() && !stop_flag)
			pkts_cv.wait_for(lck, 500ms);

		if (pkts.empty() || stop_flag)
			continue;

		const packet *pkt = pkts.at(0);
		pkts.erase(pkts.begin());

		lck.unlock();

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

	listeners.insert({ port, tph });
}

void tcp::send_data(tcp_session_t *const ts, const uint8_t *const data, const size_t len)
{
	uint64_t internal_id = get_us();

	dolog(debug, "TCP[%012" PRIx64 "]: send frame, %zu bytes, internal id: %lu, %lu packets\n", ts->id, len, internal_id, (len + ts->window_size - 1) / ts->window_size);
	std::string content = bin_to_text(data, std::min(len, size_t(32)));
	dolog(debug, "TCP[%012" PRIx64 "]: %s\n", ts->id, content.c_str());

	for(;;) {
		// lock for unacked and for my_seq_nr
		std::unique_lock<std::mutex> lck(ts->tlock);

		if (ts->unacked_size < 1024 * 1024)  // max 1MB queued
			break;

		if (ts->state != tcp_established) {
			dolog(debug, "TCP[%012" PRIx64 "]: send_data interrupted by session end\n", ts->id);
			break;
		}

		ts->unacked_sent_cv.wait_for(lck, 100ms);

		dolog(debug, "TCP[%012" PRIx64 "]: unacked-buffer full\n", ts->id);
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
		dolog(debug, "TCP[%012" PRIx64 "]: end session, seq %u\n", ts->id, rel_seqnr(ts, true, ts->my_seq_nr));

		send_segment(ts, ts->id, ts->org_dst_addr, ts->org_dst_port, ts->org_src_addr, ts->org_src_port, 1, FLAG_FIN, ts->their_seq_nr, &ts->my_seq_nr, nullptr, 0);

		ts->state = tcp_fin_wait_1;
	}
	else {
		dolog(debug, "TCP[%012" PRIx64 "]: schedule end session, after %d bytes\n", ts->id, ts->unacked_size);

		ts->fin_after_unacked_empty = true;
	}
}
