// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under AGPL v3.0
#include <assert.h>
#include <atomic>
#include <chrono>
#include <inttypes.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "tcp.h"
#include "ipv4.h"
#include "icmp.h"
#include "utils.h"

using namespace std::chrono_literals;

void free_tcp_session(tcp_session_t *const p)
{
	delete p->p;

	while(p->unacked.empty() == false) {
		delete [] p->unacked.front().second.data;

		p->unacked.pop_front();
	}

	delete p;
}

int queue_size(const std::deque<std::pair<uint32_t, unacked_segment_t> > & q)
{
	int size = 0;

	for(auto qe : q)
		size += qe.second.len; // FIXME ip-header size

	return size;
}

uint16_t tcp_checksum(const std::pair<const uint8_t *, int> src_addr, const std::pair<const uint8_t *, int> dst_addr, const uint8_t *const tcp_payload, const int len)
{
	size_t temp_len = 12 + len + (len & 1);
	uint8_t *temp = new uint8_t[temp_len]();

	temp[0] = src_addr.first[0];
	temp[1] = src_addr.first[1];
	temp[2] = src_addr.first[2];
	temp[3] = src_addr.first[3];

	temp[4] = dst_addr.first[0];
	temp[5] = dst_addr.first[1];
	temp[6] = dst_addr.first[2];
	temp[7] = dst_addr.first[3];

	temp[9] = 0x06; // TCP

	temp[10] = len >> 8; // TCP len
	temp[11] = len;

	memcpy(&temp[12], tcp_payload, len);

	uint16_t checksum = ipv4_checksum((const uint16_t *)temp, temp_len / 2);

	delete [] temp;

	return checksum;
}

char *flags_to_str(uint8_t flags)
{
	char *out = (char *)calloc(1, 128);

	if (flags & (1 << 7))
		strcat(out, "CWR,");
	if (flags & (1 << 6))
		strcat(out, "ECE,");
	if (flags & (1 << 5))
		strcat(out, "URG,");
	if (flags & (1 << 4))
		strcat(out, "ACK,");
	if (flags & (1 << 3))
		strcat(out, "PSH,");
	if (flags & (1 << 2))
		strcat(out, "RST,");
	if (flags & (1 << 1))
		strcat(out, "SYN,");
	if (flags & (1 << 0))
		strcat(out, "FIN,");

	return out;
}

tcp::tcp(stats *const s, icmp *const icmp_) : icmp_(icmp_)
{
	tcp_packets = s->register_stat("tcp_packets");
	tcp_errors = s->register_stat("tcp_errors");
	tcp_succ_estab = s->register_stat("tcp_succ_estab");
	tcp_internal_err = s->register_stat("tcp_internal_err");
	tcp_syn = s->register_stat("tcp_syn");
	tcp_new_sessions = s->register_stat("tcp_new_sessions");
	tcp_sessions_rem = s->register_stat("tcp_sessions_rem");
	tcp_sessions_to = s->register_stat("tcp_sessions_to");
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

void tcp::send_segment(const uint64_t session_id, const std::pair<const uint8_t *, int> my_addr, const int my_port, const std::pair<const uint8_t *, int> peer_addr, const int peer_port, const int org_len, const uint8_t flags, const uint32_t ack_to, uint32_t *const my_seq_nr, const uint8_t *const data, const size_t data_len)
{
	char *flag_str = flags_to_str(flags);
	dolog("TCP[%012" PRIx64 "]: Sending segment (flags: %02x (%s)), ack to: %u, my seq: %u, len: %zu)\n", session_id, flags, flag_str, ack_to, my_seq_nr ? *my_seq_nr : -1, data_len);
	free(flag_str);

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
	
	uint16_t checksum = tcp_checksum(peer_addr, my_addr, temp, temp_len);

	temp[16] = checksum >> 8;
	temp[17] = checksum;

	idev->transmit_packet(peer_addr.first, my_addr.first, 0x06, temp, temp_len);

	delete [] temp;

	if (my_seq_nr)
		(*my_seq_nr) += data_len;
}

void tcp::packet_handler(const packet *const pkt, std::atomic_bool *const finished_flag)
{
	const uint8_t *const p = pkt->get_data();
	const int size = pkt->get_size();

	if (size < 20) {
		dolog("TCP: packet too short\n");
		delete pkt;
		stats_inc_counter(tcp_errors);
		*finished_flag = true;
		return;
	}

	// FIXME verify checksum

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
	uint64_t id = src.first[0] | (src.first[1] << 8) | (src.first[2] << 16) | uint32_t(src.first[3] << 24) | (uint64_t(src_port) << 32);

	char *flag_str = flags_to_str(p[13]);
	dolog("TCP[%012" PRIx64 "]: packet %d->%d, flags: %02x (%s), their seq: %u, ack to: %u, chksum: 0x%04x, size: %d\n", id, src_port, dst_port, p[13], flag_str, their_seq_nr, ack_to, (p[16] << 8) | p[17], size);
	free(flag_str);

	dolog("TCP[%012" PRIx64 "]: sessions lock (by TID %d)\n", id, gettid());
	sessions_lock.lock();

	auto cur_it = sessions.find(id);

	if (cur_it == sessions.end()) {
		tcp_session_t *new_session = new tcp_session_t();
		new_session->state_me = tcp_listen;
		new_session->last_pkt = get_us();

		get_random((uint8_t *)&new_session->my_seq_nr, sizeof new_session->my_seq_nr);
		new_session->last_acked_to = new_session->my_seq_nr;

		new_session->their_seq_nr = their_seq_nr + 1;

		new_session->id = id;

		new_session->window_size = win_size;

		memcpy(new_session->org_src_addr.first, pkt->get_src_addr().first, 4);
		new_session->org_src_addr.second = pkt->get_src_addr().second;
		new_session->org_src_port = src_port;
		dolog("src: %08x %d\n", *(uint32_t *)new_session->org_src_addr.first, new_session->org_src_port);

		memcpy(new_session->org_dst_addr.first, pkt->get_dst_addr().first, 4);
		new_session->org_dst_addr.second = pkt->get_dst_addr().second;
		new_session->org_dst_port = dst_port;
		dolog("dst: %08x %d\n", *(uint32_t *)new_session->org_dst_addr.first, new_session->org_dst_port);

		new_session->p = nullptr;
		new_session->t = this;

		sessions.insert({ id, new_session });

		stats_inc_counter(tcp_new_sessions);

		dolog("TCP[%012" PRIx64 "]: ...is a new session\n", id);

		cur_it = sessions.find(id);
	}

	tcp_session_t *const cur_session = cur_it->second;

	dolog("TCP[%012" PRIx64 "]: start processing, state: %d, window size: %d\n", id, cur_session->state_me, win_size);
	cur_session->tlock.lock();

	// FIXME ask physical layer for max. size of packet and use that unless other send_segment() invocations pushes
	// data of 512(?) bytes or less
	cur_it->second->window_size = std::max(1500, win_size);

	bool fail = false;
	bool delete_entry = false;

	if (header_size > size) {
		dolog("TCP[%012" PRIx64 "]: header with options > packet size\n", id);
		fail = true;
	}
	else if (cb_it == listeners.end()) {
		dolog("TCP[%012" PRIx64 "]: no listener for that port\n", id);
		fail = true;
	}
	else if (flag_fin) {
		if (cur_session->state_me != tcp_listen) {
			dolog("TCP[%012" PRIx64 "]: FIN, send ACK + FIN\n", id);

			cur_session->their_seq_nr = their_seq_nr + 1;

			uint8_t flags = 1 << 4; // ACK

			if (cur_session->state_me != tcp_fin_wait1)
				flags |= 1 << 0; // FIN

			if (idev)
				send_segment(id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, flags, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0);

			if (cur_session->state_me == tcp_established)
				cur_session->state_me = tcp_fin_wait1;
			else if (cur_session->state_me == tcp_fin_wait1)
				cur_session->state_me = tcp_fin_wait2;
			else if (cur_session->state_me == tcp_fin_wait2)
				cur_session->state_me = tcp_wait;
			else {
				dolog("TCP[%012" PRIx64 "]: unexpected state %d during FIN handling\n", id, cur_session->state_me);
				stats_inc_counter(tcp_internal_err);
			}

			cur_session->my_seq_nr++;

			cb_it->second.session_closed(cur_session, cb_it->second.private_data);
		}
		else {
			dolog("TCP[%012" PRIx64 "]: FIN for unknown session\n", id);
			fail = true;
		}

		delete_entry = true;
	}
	else if (flag_syn) {
		if (!flag_ack)
			stats_inc_counter(tcp_syn);

		if (cur_session->state_me != tcp_listen)
			dolog("TCP[%012" PRIx64 "]: session already on-going\n", id);
		else {
			cur_session->state_me = tcp_sync_recv;

			send_segment(id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, (1 << 1) | (1 << 4) /* SYN, ACK */, cur_session->their_seq_nr, &cur_session->my_seq_nr, nullptr, 0);
			cur_session->my_seq_nr++;

			dolog("TCP[%012" PRIx64 "]: SYN/ACK sent\n", id);
		}
	}
	else if (flag_ack) {
		if (cur_session->state_me != tcp_listen) {
			if (cur_session->state_me == tcp_sync_recv) {
				cur_session->state_me = tcp_established;
				stats_inc_counter(tcp_succ_estab);

				dolog("TCP[%012" PRIx64 "]: session established\n", id);

				if (cb_it->second.new_session(cur_session, pkt, cb_it->second.private_data) == false) {
					dolog("TCP[%012" PRIx64 "]: session terminated\n", id);
					fail = true;
				}
			}
			else if (cur_session->state_me == tcp_fin_wait2) {
				dolog("TCP[%012" PRIx64 "]: final ACK received for FIN\n", id);
				cur_session->state_me = tcp_wait;
			}
			else if (cur_session->state_me == tcp_established) {
				// FIXME un-queue packet with acked seq-nr
			}
			else {
				dolog("TCP[%012" PRIx64 "]: unexpected state %d during ACK handling\n", id, cur_session->state_me);
				stats_inc_counter(tcp_internal_err);
			}
		}
		else {
			dolog("TCP[%012" PRIx64 "]: ACK for unknown session\n", id);
			fail = true;
		}
	}
	else if (flag_rst) {
		dolog("TCP[%012" PRIx64 "]: RST\n", id);
		delete_entry = true;
		stats_inc_counter(tcp_rst);
	}

	if (flag_ack && cur_session) {
		int n_acked = 0;

		// delete acked
		while(cur_session->unacked.empty() == false && cur_session->unacked.front().first <= ack_to) {  // FIXME < ack_to?
			dolog("TCP[%012" PRIx64 "]: got ack for %u (ack to: %u, internal id: %lu)\n", id, cur_session->unacked.front().first, ack_to, cur_session->unacked.front().second.internal_id);

			delete [] cur_session->unacked.front().second.data;

			cur_session->unacked.pop_front();

			n_acked++;
		}

		cur_session->last_acked_to = ack_to;

		if (n_acked)
			sessions_cv.notify_all();

		dolog("TCP[%012" PRIx64 "]: ACK for %u (%d acked, %zu left)\n", id, ack_to, n_acked, cur_session->unacked.size());
	}

	int data_len = size - header_size;
	if (data_len > 0 && fail == false && cur_session) {
		dolog("TCP[%012" PRIx64 "]: packet len %d, header size: %d, data size: %d\n", id, size, header_size, data_len);

		send_segment(id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, (1 << 4) /* ACK */, their_seq_nr + data_len, &cur_session->my_seq_nr, nullptr, 0);

		if (cb_it->second.new_data(cur_session, pkt, &p[header_size], data_len, cb_it->second.private_data) == false)
			fail = true;
	}

	if (fail) {
		if (cb_it != listeners.end())
			cb_it->second.session_closed(cur_session, cb_it->second.private_data);

		stats_inc_counter(tcp_errors);

		delete_entry = true;

		if (idev) {
			dolog("TCP[%012" PRIx64 "]: sending fail packet\n", id);
			send_segment(id, cur_session->org_dst_addr, cur_session->org_dst_port, cur_session->org_src_addr, cur_session->org_src_port, win_size, (1 << 2) | (1 << 4) /* RST, ACK */, their_seq_nr + 1, nullptr, nullptr, 0);
		}
	}
	else {
		cur_session->last_pkt = get_us();
	}

	cur_session->tlock.unlock();

	sessions_lock.unlock();
	dolog("sessions_lock.unlock TID %d net voor delete_entry\n", gettid());

	if (delete_entry) {
		dolog("TCP sessions_lock.lock by TID %d, in delete_entry\n", gettid());
		sessions_lock.lock();

		cur_it = sessions.find(id);

		if (cur_it != sessions.end()) {
			// call session_closed
			auto cb_it = listeners.find(cur_it->second->org_dst_port);

			if (cb_it != listeners.end())  // session not initiated here?
				cb_it->second.session_closed(cur_it->second, cb_it->second.private_data);

			// clean-up
			free_tcp_session(cur_it->second);

			sessions.erase(cur_it);
		}

		stats_inc_counter(tcp_sessions_rem);

		sessions_lock.unlock();
		dolog("TCP sessions_lock.unlock by %d in delete_entry\n", gettid());
	}

	delete pkt;

	*finished_flag = true;
}

void tcp::session_cleaner()
{
	set_thread_name("tcp-clnr");

	while(!stop_flag) {
		dolog("tcp-clnr sleep %d seconds\n", clean_interval);

		using namespace std::chrono_literals;

		std::unique_lock<std::mutex> lck(sessions_lock);
		if (pkts_cv.wait_for(lck, 1s) == std::cv_status::no_timeout)
			dolog("tcp-clnr woke-up after ack\n");

		// find t/o'd sessions
		uint64_t now = get_us();

		dolog("tcp-clnr sessions_lock.lock TID %d\n", gettid());

		for(auto it = sessions.cbegin(); it != sessions.cend();) {
			if ((now - it->second->last_pkt) / 1000000 >= session_timeout) {
				dolog("TCP[%012" PRIx64 "]: session timed out\n", it->first);

				// call session_closed
				auto cb_it = listeners.find(it->second->org_dst_port);

				if (cb_it != listeners.end())  // session not initiated here?
					cb_it->second.session_closed(it->second, cb_it->second.private_data);

				// clean-up
				free_tcp_session(it->second);

				it = sessions.erase(it);

				stats_inc_counter(tcp_sessions_to);

				// FIXME send a FIN? RST?
			}
			else {
				++it;
			}
		}

		lck.unlock();
		dolog("tcp-clnr sessions_lock.unlock %d\n", gettid());

		// go through all sessions and find if any has segments to resend
		lck.lock();

		dolog("tcp-clnr SEND UNACKED FOR %zu SESSIONS\n", sessions.size());
		for(auto it = sessions.cbegin(); it != sessions.cend(); it++) {
			it->second->tlock.lock();

			int n_resend = 0;

			now = get_us();

			// find unacked
			dolog("tcp-clnr %zu segments pending for %012" PRIx64 "\n", it->second->unacked.size(), it->second->id);
			for(auto s_it = it->second->unacked.begin(); s_it != it->second->unacked.end(); s_it++) {
				uint32_t resend_nr = s_it->first;

				if (resend_nr + s_it->second.len > it->second->last_acked_to + it->second->window_size)
					break;

				dolog("tcp-clnr SEND for seq.nr.: %lu, internal id: %lu\n", resend_nr, s_it->second.internal_id);

				send_segment(it->second->id, it->second->org_dst_addr, it->second->org_dst_port, it->second->org_src_addr, it->second->org_src_port, 0, (1 << 4) /* ACK */, it->second->their_seq_nr, &resend_nr, s_it->second.data, s_it->second.len);

				assert(resend_nr == s_it->first + s_it -> second.len);

				s_it->second.last_sent = now;

				n_resend++;

				now = get_us();
			}

			it->second->tlock.unlock();
		}
		dolog("tcp-clnr SEND UNACKED finished\n");

		lck.unlock();
	}
}

void tcp::operator()()
{
	set_thread_name("tcp");

	std::thread *cleaner = new std::thread(&tcp::session_cleaner, this);

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

		// FIXME zolang tcp::packet_handler 1 grote lock heeft, niet dit
#if 0
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
#endif
		packet_handler(pkt, &handler_data->finished_flag);
		delete handler_data;
	}

	// FIXME stop the cleaner thread
	cleaner->join();
	delete cleaner;
}

void tcp::add_handler(const int port, tcp_port_handler_t & tph)
{
	if (tph.init)
		tph.init();

	listeners.insert({ port, tph });
}

void tcp::send_data(tcp_session_t *const ts, const uint8_t *const data, const size_t len, const bool in_cb)
{
	uint64_t internal_id = get_us();

	// FIXME fragment depending on MTU size
	constexpr int block_size = 1280;

	dolog("TCP[%012" PRIx64 "]: send frame, %zu bytes, tid: %d, internal id: %lu, %u packets\n", ts->id, len, gettid(), internal_id, (len + block_size - 1) / block_size);

	for(size_t i=0; i<len; i += block_size) {
		const uint8_t *p = &data[i];

		size_t p_len = len - i;
		if (p_len > block_size)
			p_len = block_size;

		// lock for unacked and for my_seq_nr
		std::unique_lock<std::mutex> *lck = nullptr;

		if (!in_cb)
			lck = new std::unique_lock<std::mutex>(ts->tlock);

		ts->unacked.push_back({ ts->my_seq_nr, { duplicate(p, p_len), p_len, get_us(), internal_id } });

		if (ts->last_acked_to + ts->window_size >= ts->my_seq_nr + p_len)  {  // FIXME tcp window size
			dolog("TCP[%012" PRIx64 "]: segment sent, peerseq: %u, myseq: %u\n", ts->id, ts->their_seq_nr, ts->my_seq_nr);

			send_segment(ts->id, ts->org_dst_addr, ts->org_dst_port, ts->org_src_addr, ts->org_src_port, 0, (1 << 4) | (1 << 3) /* ACK, PSH */, ts->their_seq_nr, &ts->my_seq_nr, p, p_len);
		}
		else {
			ts->my_seq_nr += p_len;
		}

		if (lck) {
			lck->unlock();
			delete lck;
		}
	}
}

// this method requires tcp_session_t to be already locked
void tcp::end_session(tcp_session_t *const ts, const packet *const pkt)
{
	dolog("TCP[%012" PRIx64 "]: end session, seq %u\n", ts->id, ts->my_seq_nr);

	const uint8_t *p = pkt->get_header().first;
	int win_size = (p[14] << 8) | p[15];

	send_segment(ts->id, ts->org_dst_addr, ts->org_dst_port, ts->org_src_addr, ts->org_src_port, win_size, (1 << 4) | (1 << 0) /* ACK, FIN */, ts->their_seq_nr, &ts->my_seq_nr, nullptr, 0);
	ts->my_seq_nr++;

	ts->state_me = tcp_fin_wait1;
}
