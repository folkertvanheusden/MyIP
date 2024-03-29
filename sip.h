// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <map>
#include <mutex>
#include <sndfile.h>
#include <stdint.h>
#include <string>
#include <thread>
#include <vector>

#include "any_addr.h"
#include "application.h"
#include "stats.h"
#include "types.h"

class packet;
class udp;

typedef struct {
	uint8_t id;
	std::string name, org_name;
	int rate;
	int frame_size;
} codec_t;

class sip_session_data : public session_data
{
public:
	uint64_t         start_ts      { 0 };
	std::atomic_bool finished      { false };

	any_addr         sip_addr_peer;
	any_addr         sip_addr_me;

	std::vector<std::string> headers;
	int              sip_port_peer { 0 };
	int              sip_port_me   { 0 };

	std::thread     *recorder      { nullptr };
	codec_t          schema        { 255, "", "", -1 };
	SNDFILE         *sf            { nullptr };
	bool             stats_done    { false };

	std::atomic_uint64_t latest_pkt { 0 };

	sip_session_data() {
	}
};

class sip : public application
{
private:
	udp *const u;

	const std::string mailbox_path, mb_recv_exec;

	const std::string upstream_server, username, password;
	const any_addr myip;
	const int myport, interval;

	std::thread *th { nullptr };
	std::thread *th2 { nullptr };  // register thread

	std::map<std::thread *, sip_session_data *> sessions;
	std::mutex slock;

	uint64_t ddos_protection { 0 };

	int samplerate { 0 }, n_samples { 0 };
	short *samples { nullptr };

	uint64_t *sip_requests { nullptr };
	uint64_t *sip_requests_unk { nullptr };
	uint64_t *sip_rtp_sessions { nullptr };
	uint64_t *sip_rtp_codec_8 { nullptr };
	uint64_t *sip_rtp_codec_11 { nullptr };
	uint64_t *sip_rtp_codec_97 { nullptr };
	uint64_t *sip_rtp_duration { nullptr };

	void reply_to_OPTIONS(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers);
	void reply_to_INVITE(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers, const std::vector<std::string> *const body, session_data *const pd);
	void voicemailbox(const any_addr & tgt_addr, const int tgt_port, const any_addr & src_addr, const int src_port, sip_session_data *const ss, session_data *const pd);
	void send_BYE(const any_addr & tgt_addr, const int tgt_port, const any_addr & src_addr, const int src_port, const std::vector<std::string> & headers);
	void transmit_audio(const any_addr & tgt_addr, const int tgt_port, const any_addr & src_addr, const int src_port, sip_session_data *const ss, const short *const samples, const int n_samples, uint16_t *const seq_nr, uint32_t *const t, const uint32_t ssrc);
	bool send_REGISTER(const std::string & call_id, const std::string & authorize);
	void register_thread();
	void reply_to_UNAUTHORIZED(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers, session_data *const pd);
	void send_ACK(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers, session_data *const pd);

public:
	sip(stats *const s, udp *const u, const std::string & sample, const std::string & mailbox_path, const std::string & mb_recv_exec, const std::string & upstream_sip_server, const std::string & upstream_sip_user, const std::string & upstream_sip_password, const any_addr & myip, const int myport, const int interval);
	sip(const sip &) = delete;
	virtual ~sip();

	void input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, session_data *const pd);

	void input_recv(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, session_data *const pd);

	void operator()();
};
