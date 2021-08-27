// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
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
#include "stats.h"

class packet;
class udp;

typedef struct _sip_session_ {
	uint64_t start_ts { 0 };
	std::atomic_bool finished { false };
	std::vector<std::string> headers;
	any_addr sip_addr_peer, sip_addr_me;
	int sip_port_peer { 0 }, sip_port_me { 0 };
	std::thread *recorder { nullptr };
	uint8_t schema { 255 };
	SNDFILE *sf { nullptr };
	bool stats_done { false };
	std::atomic_uint64_t latest_pkt { 0 };

	_sip_session_() {
	}

} sip_session_t;

class sip
{
private:
	udp *const u;

	std::thread *th { nullptr };
	std::atomic_bool stop_flag { false };

	std::map<std::thread *, sip_session_t *> sessions;
	std::mutex slock;

	int samplerate { 0 }, n_samples { 0 };
	short *samples { nullptr };

	std::string mailbox_path { "/tmp" };

	uint64_t *sip_requests { nullptr };
	uint64_t *sip_requests_unk { nullptr };
	uint64_t *sip_rtp_sessions { nullptr };
	uint64_t *sip_rtp_codec_8 { nullptr };
	uint64_t *sip_rtp_codec_11 { nullptr };
	uint64_t *sip_rtp_codec_97 { nullptr };
	uint64_t *sip_rtp_duration { nullptr };

	void reply_to_OPTIONS(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers);
	void reply_to_INVITE(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers, const std::vector<std::string> *const body, void *const pd);
	void voicemailbox(const any_addr & tgt_addr, const int tgt_port, const any_addr & src_addr, const int src_port, sip_session_t *const ss, void *const pd);
	void send_BYE(const any_addr & tgt_addr, const int tgt_port, const any_addr & src_addr, const int src_port, const std::vector<std::string> & headers);

public:
	sip(stats *const s, udp *const u, const std::string & sample, const std::string & mailbox_path);
	sip(const sip &) = delete;
	virtual ~sip();

	void input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, void *const pd);

	void input_recv(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, void *const pd);

	void operator()();
};
