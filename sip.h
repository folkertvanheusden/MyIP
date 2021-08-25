// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <map>
#include <mutex>
#include <stdint.h>
#include <string>
#include <thread>
#include <vector>

#include "any_addr.h"
#include "stats.h"

class packet;
class udp;

typedef struct _sip_session_ {
	uint64_t start_ts;
	std::atomic_bool finished;

	_sip_session_() {
		start_ts = 0;
		finished = false;
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
	uint8_t *samples { nullptr };

	void reply_to_OPTIONS(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers);
	void reply_to_INVITE(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers, const std::vector<std::string> *const body);
	void transmit_wav(const any_addr & tgt_addr, const int tgt_port, const any_addr & src_addr, const int src_port, sip_session_t *const ss);

public:
	sip(stats *const s, udp *const u, const std::string & sample);
	sip(const sip &) = delete;
	virtual ~sip();

	void input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p);

	void operator()();
};
