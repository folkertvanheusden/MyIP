// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include "hash.h"
#include "ipv4.h"
#include "log.h"
#include "stats-utils.h"
#include "str.h"
#include "tcp.h"
#include "types.h"
#include "utils.h"


void send_response(tcp_session_t *ts, struct timespec tv, uint8_t *request, int32_t data_len, private_data *pd);

using namespace std::chrono_literals;

void nrpe_thread(tcp_session_t *t_s, struct timespec tv, private_data *pd)
{
        set_thread_name("myip-nrpe");

        nrpe_session_data *ts = dynamic_cast<nrpe_session_data *>(t_s->p);

        for(;ts->terminate == false;) {
		std::unique_lock<std::mutex> lck(ts->r_lock);

		if (ts->req_data) {
			if (ts->req_len >= 16) {
				int32_t buffer_length = (ts->req_data[12] << 24) | (ts->req_data[13] << 16) | (ts->req_data[14] << 8) | ts->req_data[15];

				if (ts->req_len >= size_t(16 + buffer_length) && buffer_length > 0)
					send_response(t_s, tv, ts->req_data, buffer_length, pd);
			}
		}

		ts->r_cond.wait_for(lck, 500ms);
	}
}

bool nrpe_new_session(tcp_session_t *t_s, const packet *pkt, private_data *pd)
{
	nrpe_session_data *ts = new nrpe_session_data();
	ts->req_data = nullptr;
	ts->req_len = 0;

	any_addr src_addr = pkt->get_src_addr();
	ts->client_addr   = src_addr.to_str();

	t_s->p = ts;

	stats_inc_counter(dynamic_cast<nrpe_private_data *>(pd)->nrpe_requests);

	ts->th = new std::thread(nrpe_thread, t_s, pkt->get_recv_ts(), pd);

	return true;
}

void send_response(tcp_session_t *t_s, struct timespec tv, uint8_t *request, int32_t data_len, private_data *pd)
{
	int         response_code    = 3;
	std::string response_payload;

	do {
		uint16_t version = (request[0] << 8) | request[1];

		if (version != 4 && version != 3)
			break;

		const char *msg = reinterpret_cast<const char *>(&request[16]);

		if (strcmp(msg, "%ALL%") == 0) {
			response_code = 0;

			response_payload = "OK";
		}
		else {
			response_code    = 3;

			response_payload = "Unknown service requested";
		}
	}
	while(0);

	struct rusage ru { 0 };

	if (getrusage(RUSAGE_SELF, &ru) == -1)
		DOLOG(warning, "NRPE: getrusage failed\n");

	// TODO cpu usage
	response_payload += myformat("|rss=%lukB;", ru.ru_maxrss);

	uint8_t reply[16 + 1024] { 0 };

	reply[0] = request[0];  // version
	reply[1] = request[1];

	reply[3] = 2;  // type (2 = response)

	reply[9] = response_code;

	reply[12] = response_payload.size() >> 24;
	reply[13] = response_payload.size() >> 16;
	reply[14] = response_payload.size() >>  8;
	reply[15] = response_payload.size() >>  0;

	memcpy(&reply[16], response_payload.c_str(), response_payload.size());

	int total_size = 16 + response_payload.size();

	uint32_t crc = crc32(reply, total_size + (request[1] == 3 ? 3 : 0), 0xedb88320);
	reply[4] = crc >> 24;
	reply[5] = crc >> 16;
	reply[6] = crc >> 8;
	reply[7] = crc;

	t_s->t->send_data(t_s, reply, total_size);

	t_s->t->end_session(t_s);
}

bool nrpe_new_data(tcp_session_t *t_s, const uint8_t *data, size_t data_len, private_data *pd)
{
	nrpe_session_data *ts = dynamic_cast<nrpe_session_data *>(t_s->p);

	if (!ts) {
		DOLOG(info, "NRPE: Data for a non-existing session\n");

		stats_inc_counter(dynamic_cast<nrpe_private_data *>(pd)->nrpe_r_err);

		return false;
	}

	if (!data) {
		DOLOG(debug, "NRPE: client closed session\n");

		stats_inc_counter(dynamic_cast<nrpe_private_data *>(pd)->nrpe_r_err);

		return true;
	}

	const std::lock_guard<std::mutex> lck(ts->r_lock);

	ts->req_data = reinterpret_cast<uint8_t *>(realloc(ts->req_data, ts->req_len + data_len + 1));

	memcpy(&ts->req_data[ts->req_len], data, data_len);
	ts->req_len += data_len;
	ts->req_data[ts->req_len] = 0x00;

	ts->r_cond.notify_one();

	return true;
}

void nrpe_close_session_1(tcp_session_t *t_s, private_data *pd)
{
	if (t_s->p) {
		nrpe_session_data *ts = dynamic_cast<nrpe_session_data *>(t_s->p);

		ts->terminate = true;

		ts->th->join();
		delete ts->th;
		ts->th = nullptr;

		free(ts->req_data);

		delete ts;

		t_s->p = nullptr;
	}
}

void nrpe_close_session_2(tcp_session_t *ts, private_data *pd)
{
}

tcp_port_handler_t nrpe_get_handler(stats *const s)
{
	tcp_port_handler_t tcp_nrpe;

	tcp_nrpe.init             = nullptr;
	tcp_nrpe.new_session      = nrpe_new_session;
	tcp_nrpe.new_data         = nrpe_new_data;
	tcp_nrpe.session_closed_1 = nrpe_close_session_1;
	tcp_nrpe.session_closed_2 = nrpe_close_session_2;
	tcp_nrpe.deinit           = nullptr;

	nrpe_private_data *npd = new nrpe_private_data();
	npd->s = s;

	// 1.3.6.1.2.1.4.57850: vanheusden.com
	// 1.3.6.1.2.1.4.57850.1: myip
	// 1.3.6.1.2.1.4.57850.1.13: nrpe
	npd->nrpe_requests = s->register_stat("nrpe_requests", "1.3.6.1.2.1.4.57850.1.13.1");
	npd->nrpe_r_err    = s->register_stat("nrpe_r_err",    "1.3.6.1.2.1.4.57850.1.13.2");

	tcp_nrpe.pd = npd;

	return tcp_nrpe;
}
