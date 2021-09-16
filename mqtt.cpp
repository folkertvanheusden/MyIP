// (C) 2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <atomic>
#include <climits>
#include <errno.h>
#include <queue>
#include <set>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tcp.h"
#include "utils.h"
#include "ipv4.h"
#include "font.h"
#include "types.h"
#include "stats.h"

void mqtt_recv_thread(void *ts_in);

typedef struct {
	tcp_session_t *ts;  // handle
	std::mutex tx_lock;
} mqtt_tx_t;

static std::atomic_bool distr_terminate { false };
static std::thread *distr_th { nullptr };
static std::mutex sessions_lck;
static std::map<std::string, mqtt_tx_t> sessions;

static void register_session(const std::string & id, const mqtt_tx_t & tx)
{
	sessions_lck.lock();
	sessions.insert(std::pair<std::string, mqtt_tx_t>(id, tx));
	sessions_lck.unlock();
}

static void unregister_session(const std::string & id);
{
	sessions_lck.lock();
	sessions.erase(id);
	sessions_lck.unlock();
}

void mqtt_distributor()
{
	for(;!distr_terminate;) {
		std::unique_lock<std::mutex> lck(ms->w_lock);

		// anything? distribute naar sessions met een andere id

		ms->w_cond.wait(lck); // deze vervangen door iets wat x tijd wacht ivm terminate check
	}
}

void mqtt_init()
{
	distr_th = new std::thread(mqtt_distributor);
}

void mqtt_deinit()
{
	distr_terminate = true;

	distr_th->join();
	delete distr_th;
}

bool mqtt_new_session(tcp_session_t *ts, const packet *pkt, void *private_data)
{
	mqtt_session_data *ms = new mqtt_session_data();

	ms->client_addr = pkt->get_src_addr().to_str();

	ts->p = ms;

	dolog(debug, "MQTT: new session with %s\n", ms->client_addr.c_str());

	ms->th = new std::thread(mqtt_recv_thread, ts);

	return true;
}

bool mqtt_new_data(tcp_session_t *ts, const packet *pkt, const uint8_t *data, size_t data_len, void *private_data)
{
	mqtt_session_data *ms = dynamic_cast<mqtt_session_data *>(ts->p);

	if (!ms) {
		dolog(info, "MQTT: Data for a non-existing session\n");
		return false;
	}

	const std::lock_guard<std::mutex> lck(ms->w_lock);

	ms->data = static_cast<uint8_t *>(realloc(ms->data, ms->data_len + data_len));
	memcpy(&ms->data[ms->data_len], data, data_len);
	ms->data_len += data_len;

	ms->w_cond.notify_one();

	return true;
}

void mqtt_get_bytes(mqtt_session_data *const ms, uint8_t *const tgt, const size_t n)
{
	std::unique_lock<std::mutex> lck(ms->w_lock);

	for(;!ms->terminate;) {
		dolog(debug, "MQTT: %zu bytes requested, %zu available\n", n, ms->data_len);

		if (ms->data_len >= n) {
			memcpy(tgt, ms->data, n);

			int move_n = ms->data_len - n;
			if (move_n > 0)
				memmove(&ms->data[0], &ms->data[n], move_n);

			ms->data_len -= n;

			break;
		}

		ms->w_cond.wait(lck);
	}
}

uint8_t mqtt_get_byte(mqtt_session_data *const ms)
{
	uint8_t tgt = 0;

	mqtt_get_bytes(ms, &tgt, 1);

	return tgt;
}

void mqtt_recv_thread(void *ts_in)
{
	set_thread_name("myip-mqtt");

	tcp_session_t *ts = (tcp_session_t *)ts_in;
	mqtt_session_data *ms = dynamic_cast<mqtt_session_data *>(ts->p);

	mqtt_tx_t tx;
	tx.ts = ts;

	const std::string unique_identifier = ts->org_src_addr.to_str() + myformat("-%02d", ts->org_src_port);
	std::string identifier;

	register_session(unique_identifier, &tx);

	for(;ms->terminate == false;) {
		uint8_t control = mqtt_get_byte(ms);
		uint32_t len = 0;

		for(;ms->terminate == false;) {
			uint8_t b = mqtt_get_byte(ms);

			len <<= 7;
			len |= b & 127;

			if ((b & 128) == 0)
				break;
		}
		
		uint8_t *mqtt_msg = new uint8_t[len + 1];
		mqtt_get_bytes(ms, mqtt_msg, len);
		mqtt_msg[len] = 0x00;  // e.g. CONNECT msg ends with strings

		uint8_t cmsg = control >> 4;
		//uint8_t cflags = control & 0x0f;

		if (cmsg == 1) {  // CONNECT
			if (len > 12) {  // should be true (variable header + at least 0x00 for identifier)
				identifier = (char *)&mqtt_msg[12];
			}

			dolog(debug, "MQTT: Connect by %s\n", identifier.c_str());

			// send CONNACK
			uint8_t reply[] = { 0x20, 0x02, 0x00 /* reserved */, 0x00 /* accepted */};

			ts->t->send_data(ts, reply, sizeof reply, false);
		}
		else if (cmsg == 8) {  // SUBSCRIBE
		}
		else {
			dolog(info, "MQTT: Unexpected command %d received\n", cmsg);
		}

		delete [] mqtt_msg;
	}

	unregister_session(unique_identifier);

	dolog(info, "MQTT: Thread terminating for %s\n", ms->client_addr.c_str());
}

void mqtt_close_session_1(tcp_session_t *ts, private_data *pd)
{
	if (ts -> p) {
		mqtt_session_data *ms = dynamic_cast<mqtt_session_data *>(ts->p);

		ms->terminate = true;

		const std::lock_guard<std::mutex> lck(ms->w_lock);
		ms->w_cond.notify_one();
	}
}

void mqtt_close_session_2(tcp_session_t *ts, private_data *pd)
{
	if (ts -> p) {
		mqtt_session_data *ms = dynamic_cast<mqtt_session_data *>(ts->p);

		ms->th->join();
		delete ms->th;

		delete ms;

		ts->p = nullptr;
	}
}

tcp_port_handler_t mqtt_get_handler(stats *const s)
{
	tcp_port_handler_t tcp_mqtt;

	tcp_mqtt.init = mqtt_init;
	tcp_mqtt.new_session = mqtt_new_session;
	tcp_mqtt.new_data = mqtt_new_data;
	tcp_mqtt.session_closed_1 = mqtt_close_session_1;
	tcp_mqtt.session_closed_2 = mqtt_close_session_2;
	tcp_mqtt.deinit = mqtt_deinit;
	tcp_mqtt.pd = nullptr;

	return tcp_mqtt;
}
