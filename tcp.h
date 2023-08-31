// (C) 2020-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <condition_variable>
#include <deque>
#include <functional>
#include <jansson.h>
#include <map>
#include <mutex>
#include <shared_mutex>

#include "any_addr.h"
#include "application.h"
#include "duration_events.h"
#include "transport_layer.h"
#include "packet.h"
#include "pstream.h"
#include "session.h"
#include "stats.h"
#include "types.h"


class ipv4;
class tcp;

constexpr int clean_interval = 1; // in seconds
constexpr int session_timeout = 300; // in seconds

typedef enum { tcp_closed, tcp_listen, tcp_syn_rcvd, tcp_syn_sent, tcp_established, tcp_fin_wait_1, tcp_fin_wait_2, tcp_close_wait, tcp_last_ack, tcp_closing, tcp_time_wait, tcp_rst_act } tcp_state_t;

class tcp_session : public session
{
public:
	bool     is_client   { false };
	bool     in_init     { false };

	uint64_t id          { 0 };

	uint16_t window_size { 512 };

	tcp_state_t state    { tcp_closed };
	time_t state_since   { 0 };

	std::map<uint32_t, std::vector<uint8_t> > fragments;

	std::condition_variable_any state_changed;
	uint64_t e_last_pkt_ts{ 0 };  // ts of last packet (transmitted or received)
	uint64_t r_last_pkt_ts{ 0 };  // ls of last received packet
	uint32_t my_seq_nr    { 0 };
	uint32_t their_seq_nr { 0 };
	uint32_t initial_my_seq_nr    { 0 };
	uint32_t initial_their_seq_nr { 0 };

	uint8_t *unacked                 { nullptr };
	uint32_t unacked_start_seq_nr    { 0       };
	size_t   data_since_last_ack     { 0       };
	size_t   unacked_size            { 0       };
	bool     fin_after_unacked_empty { false   };
	std::condition_variable unacked_sent_cv;

	uint32_t seq_for_fin_when_all_received { 0     };
	bool     flag_fin_when_all_received    { false };

public:
	tcp_session(pstream *const t, const any_addr & my_addr, const int my_port, const any_addr & their_addr, const int their_port, private_data *app_private_data) :
		session(t, my_addr, my_port, their_addr, their_port, app_private_data) {
	}

	~tcp_session() {
	}

	std::string get_state_name() const {
		const std::string state_names[] { "closed", "listen", "syn_rcvd", "syn_sent", "established", "fin_wait_1", "fin_wait_2", "close_wait", "last_ack", "closing", "time_wait", "rst_act" };

		return state_names[state];
	}
};

typedef struct {
	std::thread *th;
	std::atomic_bool finished_flag;
} tcp_packet_handle_thread_t;

typedef struct {
	uint64_t id;
	int port;
} tcp_client_t;

class tcp : public transport_layer, public pstream
{
private:
	icmp        *const icmp_       { nullptr };

	std::thread *th_unacked_sender { nullptr };

	fifo<session *> *ending_sessions     { nullptr };
	std::vector<std::thread *> th_enders { nullptr };

	std::thread *th_cleaner        { nullptr };

	std::condition_variable_any unacked_cv;

	// listen port -> handler
	std::shared_mutex             listeners_lock;
	std::map<int, port_handler_t> listeners;

	// client port -> session
	std::map<int, uint64_t>       tcp_clients;

	uint64_t *tcp_packets           { nullptr };
	uint64_t *tcp_errors            { nullptr };
	uint64_t *tcp_succ_estab        { nullptr };
	uint64_t *tcp_internal_err      { nullptr };
	uint64_t *tcp_syn               { nullptr };
	uint64_t *tcp_new_sessions      { nullptr };
	uint64_t *tcp_sessions_rem      { nullptr };
	uint64_t *tcp_sessions_to       { nullptr };
	uint64_t *tcp_rst               { nullptr };
	uint64_t *tcp_sessions_closed_1 { nullptr };
	uint64_t *tcp_sessions_closed_2 { nullptr };
	uint64_t *tcp_cur_n_sessions    { nullptr };

	uint64_t *tcp_unacked_duration_max { nullptr };
	uint64_t *tcp_phandle_duration_max { nullptr };

	duration_events new_session_handling1 { "new session1",    8 };
	duration_events new_session_handling2 { "new session2",    8 };
	duration_events new_session_handling3 { "new session3",    8 };
	duration_events main_packet_handling  { "main packet",     8 };
	duration_events delete_session        { "delete session",  8 };
	duration_events notify_unacked        { "notify unacked",  8 };
	duration_events session_cleaner_de    { "session cleaner", 8 };
	duration_events unacked_sender_de     { "unacked sender",  8 };
	duration_events session_ender_de      { "session ender",   8 };
	duration_events send_data_de          { "send data",       8 };
	duration_events end_session_de        { "end session",     8 };
	duration_events allocate_client       { "allocate client", 8 };
	duration_events close_client          { "close client",    8 };
	duration_events send_segment_de       { "send segment",    8 };

	void send_rst_for_port(const packet *const pkt, const int dst_port, const int src_port);

	bool send_segment(tcp_session *const ts, const uint64_t session_id, const any_addr & my_addr, const int my_port, const any_addr & peer_addr, const int peer_port, const int org_len, const uint8_t flags, const uint32_t ack_to, uint32_t *const my_seq_nr, const uint8_t *const data, const size_t data_len, const uint32_t TSencr);

	void packet_handler(packet *const pkt);
	void cleanup_session_helper(std::map<uint64_t, tcp_session *>::iterator *it);
	void session_cleaner();
	void unacked_sender();
	void session_ender();

	void set_state(tcp_session *const session, const tcp_state_t new_state);

	std::optional<port_handler_t> get_lock_listener(const int dst_port, const std::string & log_prefix, const bool write_lock);
	void release_listener_lock(const bool write_lock);

	void free_tcp_session(tcp_session *const p);

public:
	tcp(stats *const s, icmp *const icmp_, const int n_threads);
	virtual ~tcp();

	json_t *get_state_json(session *const ts) override;

	void add_handler(const int port, port_handler_t & tph);

	bool send_data(session *const ts, const uint8_t *const data, const size_t len) override;
	void end_session(session *const ts) override;

	// returns a port number
	int allocate_client_session(const std::function<bool(pstream *const ps, session *const s, buffer_in data)> & new_data, const std::function<bool(pstream *const ps, session *const s)> & session_closed_2, const any_addr & dst_addr, const int dst_port, session_data *const sd);
	bool client_session_send_data(const int local_port, const uint8_t *const data, const size_t len);
	void close_client_session(const int port);
	bool wait_for_client_connected_state(const int local_port);

	virtual void operator()() override;
};
