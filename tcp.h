// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <shared_mutex>

#include "any_addr.h"
#include "ip_protocol.h"
#include "packet.h"
#include "stats.h"
#include "types.h"

class icmp;
class ipv4;
class tcp;

constexpr int clean_interval = 1; // in seconds
constexpr int session_timeout = 60; // in seconds

typedef enum { tcp_listen, tcp_sync_recv, tcp_established, tcp_fin_wait1, tcp_fin_wait2, tcp_wait } tcp_state_t;

typedef struct {
	const uint8_t *data;
	size_t len;
	uint64_t last_sent;
	uint64_t internal_id;
} unacked_segment_t;

typedef struct {
	std::mutex tlock;

	tcp *t;

	any_addr org_src_addr;
	int org_src_port;

	any_addr org_dst_addr;
	int org_dst_port;

	uint64_t id;

	uint16_t window_size;

	tcp_state_t state_me;
	uint64_t last_pkt;
	uint32_t my_seq_nr, their_seq_nr;

	uint8_t *unacked;
	size_t unacked_size;
	bool fin_after_unacked_empty;

	session_data *p;
} tcp_session_t;

typedef struct {
	std::function<void()> init;
	std::function<bool(tcp_session_t *, const packet *pkt, private_data *)> new_session;
	std::function<bool(tcp_session_t *, const packet *pkt, const uint8_t *data, size_t len, private_data *)> new_data;
	std::function<void(tcp_session_t *, private_data *)> session_closed_1;  // please terminate
	std::function<void(tcp_session_t *, private_data *)> session_closed_2;  // should be terminated, clean up
	std::function<void()> deinit;
	private_data *pd;
} tcp_port_handler_t;

typedef struct {
	std::thread *th;
	std::atomic_bool finished_flag;
} tcp_packet_handle_thread_t;

class tcp : public ip_protocol
{
private:
	icmp *const icmp_;

	std::mutex sessions_lock;
	std::condition_variable sessions_cv, unacked_cv;
	// the key is an 'internal id'
	std::map<uint64_t, tcp_session_t *> sessions;

	std::map<int, tcp_port_handler_t> listeners;

	uint64_t *tcp_packets { nullptr };
	uint64_t *tcp_errors { nullptr };
	uint64_t *tcp_succ_estab { nullptr };
	uint64_t *tcp_internal_err { nullptr };
	uint64_t *tcp_syn { nullptr };
	uint64_t *tcp_new_sessions { nullptr };
	uint64_t *tcp_sessions_rem { nullptr };
	uint64_t *tcp_sessions_to { nullptr };
	uint64_t *tcp_rst { nullptr };
	uint64_t *tcp_sessions_closed_1 { nullptr };
	uint64_t *tcp_sessions_closed_2 { nullptr };

	void send_segment(const uint64_t session_id, const any_addr & my_addr, const int my_port, const any_addr & peer_addr, const int peer_port, const int org_len, const uint8_t flags, const uint32_t ack_to, uint32_t *const my_seq_nr, const uint8_t *const data, const size_t data_len);

	void packet_handler(const packet *const pkt, std::atomic_bool *const finished_flag);
	void cleanup_session_helper(std::map<uint64_t, tcp_session_t *>::iterator *it);
	void session_cleaner();
	void unacked_sender();

public:
	tcp(stats *const s, icmp *const icmp_);
	virtual ~tcp();

	void add_handler(const int port, tcp_port_handler_t & tph);

	void send_data(tcp_session_t *const ts, const uint8_t *const data, const size_t len, const bool in_cb);
	void end_session(tcp_session_t *const ts, const packet *const pkt);

	virtual void operator()() override;
};
