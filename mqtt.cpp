// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <atomic>
#include <climits>
#include <errno.h>
#include <set>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tcp.h"
#include "str.h"
#include "utils.h"
#include "ipv4.h"
#include "font.h"
#include "log.h"
#include "types.h"
#include "stats.h"


void mqtt_recv_thread(void *ts_in);

static std::mutex topic_lck;
static std::map<const std::string, std::set<mqtt_session_data *> > topic_subscriptions;
static std::vector<std::pair<const std::string, std::set<mqtt_session_data *> > > topic_wc_subscriptions;  // wildcards

static void register_topic(const std::string & topic, mqtt_session_data *const msd)
{
	DOLOG(debug, "MQTT: Register topic %s for %p\n", topic.c_str(), msd);
	DOLOG(debug, "MQTT: # topics: %zu\n", topic_subscriptions.size());

	size_t wc = topic.find('#');
	if (wc == std::string::npos) {
		topic_lck.lock();

		auto it = topic_subscriptions.find(topic);
		if (it != topic_subscriptions.end())
			it->second.insert(msd);
		else
			topic_subscriptions.insert({ topic, { msd } });

		DOLOG(debug, "MQTT: topic %s %zu subscribers\n", topic.c_str(), topic_subscriptions.find(topic)->second.size());

		topic_lck.unlock();
	}
	else {
		topic_lck.lock();

		bool found = false;
		for(auto it : topic_wc_subscriptions) {
			if (it.first == topic) {
				it.second.insert(msd);
				found = true;
				DOLOG(debug, "MQTT: topic %s %zu subscribers\n", topic.c_str(), it.second.size());
				break;
			}
		}

		if (!found) {
			topic_wc_subscriptions.push_back({ topic, { msd } });
			DOLOG(debug, "MQTT: topic %s 1 subscriber\n", topic.c_str());
		}

		topic_lck.unlock();
	}
}

static void unregister_topic(const std::string & topic, mqtt_session_data *const msd)
{
	DOLOG(debug, "MQTT: Unregister topic %s for %p\n", topic.c_str(), msd);
	topic_lck.lock();

	auto it = topic_subscriptions.find(topic);
	if (it != topic_subscriptions.end())
		it->second.erase(msd);

	for(auto it : topic_wc_subscriptions) {
		if (it.first == topic) {
			it.second.erase(msd);
			break;
		}
	}

	topic_lck.unlock();
}

static void unregister_all_topics(mqtt_session_data *const msd)
{
	DOLOG(debug, "MQTT(%s): Unsubscribe %p from all topics\n", msd->session_name.c_str(), msd);

	topic_lck.lock();

	for(auto it : topic_subscriptions)
		it.second.erase(msd);

	for(auto it : topic_wc_subscriptions)
		it.second.erase(msd);

	topic_lck.unlock();
}

static void publish(mqtt_session_data *const msd, const std::string & topic, const uint8_t *const data, const size_t data_len)
{
	DOLOG(debug, "MQTT(%s): Publishing %ld bytes to topic %s\n", msd->session_name.c_str(), data_len, topic.c_str());

	std::vector<uint8_t> msg;
	msg.push_back(3 << 4);  // PUBLISH

	// msg length
	int var_header_len = 2 + topic.size();
	int rem_len = var_header_len + data_len;
	while(rem_len > 0) {
		if (rem_len > 127)
			msg.push_back(127 | 128);
		else
			msg.push_back(rem_len);

		rem_len >>= 7;
	}

	size_t ts = topic.size();
	msg.push_back(ts >> 8);  // topic len
	msg.push_back(ts & 255);  // topic len
	for(size_t i=0; i<ts; i++)  // topic name
		msg.push_back(topic.at(i));

	for(size_t i=0; i<data_len; i++)  // payload
		msg.push_back(data[i]);

	topic_lck.lock();

	for(auto t_it : topic_subscriptions) {
		if (t_it.first != topic)
			continue;

		for(auto s_it : t_it.second) {
			DOLOG(debug, "MQTT(%s): queuing for %p (new #: %zu)\n", msd->session_name.c_str(), s_it, s_it->msgs_out.size() + 1);

			const std::lock_guard<std::mutex> lck(s_it->w_lock);

			s_it->msgs_out.push_back({ duplicate(msg.data(), msg.size()), msg.size() });

			s_it->w_cond.notify_one();
		}
	}

	for(auto t_it : topic_wc_subscriptions) {
		size_t wc = t_it.first.find('#');
		assert(wc != std::string::npos);

		if (topic.substr(0, wc) != t_it.first.substr(0, wc))
			continue;

		for(auto s_it : t_it.second) {
			DOLOG(debug, "MQTT(%s): queuing for %p (new #: %zu)\n", msd->session_name.c_str(), s_it, s_it->msgs_out.size() + 1);

			const std::lock_guard<std::mutex> lck(s_it->w_lock);

			s_it->msgs_out.push_back({ duplicate(msg.data(), msg.size()), msg.size() });

			s_it->w_cond.notify_one();
		}
	}

	topic_lck.unlock();
}

void mqtt_init()
{
}

void mqtt_deinit()
{
}

bool mqtt_new_session(pstream *const t, session *ts)
{
	mqtt_session_data *ms = new mqtt_session_data();

	ms->session_name = ms->client_addr = ts->get_their_addr().to_str();

	ts->set_callback_private_data(ms);

	DOLOG(debug, "MQTT: new session with %s\n", ms->client_addr.c_str());

	ms->th = new std::thread(mqtt_recv_thread, ts);

	return true;
}

bool mqtt_new_data(pstream *ps, session *ts, buffer_in b)
{
	mqtt_session_data *ms = static_cast<mqtt_session_data *>(ts->get_callback_private_data());

	if (!ms) {
		DOLOG(info, "MQTT: Data for a non-existing session\n");
		return false;
	}

	int data_len = b.get_n_bytes_left();

	if (data_len == 0) {
		DOLOG(debug, "MQTT: client closed session\n");
		ms->w_cond.notify_one();
		return true;
	}

	const std::lock_guard<std::mutex> lck(ms->w_lock);

	ms->data = static_cast<uint8_t *>(realloc(ms->data, ms->data_len + data_len));
	memcpy(&ms->data[ms->data_len], b.get_bytes(data_len), data_len);
	ms->data_len += data_len;

	ms->w_cond.notify_one();

	return true;
}

// 2nd mqtt event loop
bool mqtt_get_bytes(tcp_session *const ts, mqtt_session_data *const msd, uint8_t *const tgt, const size_t n)
{
	DOLOG(debug, "MQTT(%s): %zu bytes requested, %zu available\n", msd->session_name.c_str(), n, msd->data_len);

	std::unique_lock<std::mutex> lck(msd->w_lock);

	for(;!msd->terminate;) {
		// process outgoing messages
		// they are placed in the queue by publishers
		if (msd->msgs_out.empty() == false) {
			DOLOG(debug, "MQTT(%s): %zu msgs pending\n", msd->session_name.c_str(), msd->msgs_out.size());

			for (auto it : msd->msgs_out) {
				DOLOG(debug, "MQTT(%s): sending message of %zu bytes length\n", msd->session_name.c_str(), it.second);

				ts->get_stream_target()->send_data(ts, it.first, it.second);
				delete [] it.first;
			}

			msd->msgs_out.clear();
		}

		// any data?
		if (msd->data_len >= n) {
			memcpy(tgt, msd->data, n);

			int move_n = msd->data_len - n;
			assert(move_n >= 0);

			if (move_n > 0)
				memmove(&msd->data[0], &msd->data[n], move_n);

			assert(msd->data_len >= n);
			msd->data_len -= n;

			break;
		}

		// no more data?
		if (ts->state >= tcp_last_ack) {
			DOLOG(debug, "MQTT(%s): (mqtt_get_bytes) no more data; session closed/closing\n", msd->session_name.c_str());

			return false;
		}

		msd->w_cond.wait(lck);
	}

	DOLOG(debug, "MQTT(%s): %zu bytes returned\n", msd->session_name.c_str(), n);

	return true;
}

bool mqtt_get_byte(tcp_session *const ts, mqtt_session_data *const ms, uint8_t *data)
{
	return mqtt_get_bytes(ts, ms, data, 1);
}

void mqtt_recv_thread(void *ts_in)
{
	set_thread_name("myip-mqtt");

	tcp_session *ts = (tcp_session *)ts_in;
	mqtt_session_data *ms = dynamic_cast<mqtt_session_data *>(ts->p);

	std::string identifier;

	for(;ms->terminate == false;) {
		uint8_t control = 0;
		if (mqtt_get_byte(ts, ms, &control) == false)
			break;

		uint32_t len = 0;

		bool finished = false;
		for(;ms->terminate == false;) {
			uint8_t b = 0;
			if (!mqtt_get_byte(ts, ms, &b)) {
				finished = true;
				break;
			}

			len <<= 7;
			len |= b & 127;

			if ((b & 128) == 0)
				break;
		}

		if (finished)
			break;

		uint8_t cmsg = control >> 4;
		//uint8_t cflags = control & 0x0f;

		DOLOG(debug, "MQTT(%s): control %02x (%d) msg %d, rem. len.: %d\n", ms->session_name.c_str(), control, control, cmsg, len);
		
		uint8_t *mqtt_msg = new uint8_t[len + 1];
		if (!mqtt_get_bytes(ts, ms, mqtt_msg, len)) {
			delete [] mqtt_msg;
			break;
		}

		mqtt_msg[len] = 0x00;  // e.g. CONNECT msg ends with strings

		std::string hex;
		for(uint32_t i=0; i<len; i++)
			hex += myformat("%02x[%c] ", mqtt_msg[i], mqtt_msg[i] >= 32 ? mqtt_msg[i] : '_');
		DOLOG(debug, "MQTT(%s): msg hex %s\n", ms->session_name.c_str(), hex.c_str());

		if (cmsg == 1) {  // CONNECT
			if (len > 12) {  // should be true (variable header + at least 0x00 for identifier)
				identifier = (char *)&mqtt_msg[12];
			}

			DOLOG(debug, "MQTT(%s): Connect by %s\n", ms->session_name.c_str(), identifier.c_str());

			if (!identifier.empty())
				ms->session_name = identifier;

			// send CONNACK
			uint8_t reply[] = { 0x20, 0x02, 0x00 /* reserved */, 0x00 /* accepted */};

			ts->get_stream_target()->send_data(ts, reply, sizeof reply);
		}
		else if (cmsg == 3) {  // PUBLISH
			int o = 0;
			int topic_len = std::min((mqtt_msg[0] << 8) | mqtt_msg[1], int(len));
			DOLOG(debug, "MQTT(%s): topic len: %d (%d | %d)\n", ms->session_name.c_str(), topic_len, (mqtt_msg[0] << 8) | mqtt_msg[1], len);
			std::string topic((const char *)&mqtt_msg[2], topic_len);
			o += 2 + topic_len;

			DOLOG(debug, "MQTT(%s): publish to %s\n", ms->session_name.c_str(), topic.c_str());

			uint16_t msg_id = 0;
			if ((control >> 1) & 3) {
				msg_id = (mqtt_msg[o] << 8) | mqtt_msg[o + 1];
				o += 2;
			}

			uint8_t *payload = &mqtt_msg[o];
			int32_t payload_len = len - o;

			if (payload_len > 0)
				publish(ms, topic, payload, payload_len);

			DOLOG(debug, "MQTT(%s): %d bytes payload (msg_id %d) for topic %s\n", ms->session_name.c_str(), payload_len, msg_id, topic.c_str());

			std::vector<uint8_t> reply;
			reply.push_back(4 << 4);
			reply.push_back(2);  // remaining length
			reply.push_back(msg_id >> 8);
			reply.push_back(msg_id & 255);

			ts->get_stream_target()->send_data(ts, reply.data(), reply.size());
		}
		else if (cmsg == 8) {  // SUBSCRIBE
			std::vector<uint8_t> reply;
			reply.push_back(0x9 << 4);  // SUBACK

			reply.push_back(0);  // will be length

			uint16_t msg_id = (mqtt_msg[0] << 8) | mqtt_msg[1];
			DOLOG(debug, "MQTT(%s): SUBSCRIBE, msg id: %d\n", ms->session_name.c_str(), msg_id);
			reply.push_back(mqtt_msg[0]);
			reply.push_back(mqtt_msg[1]);

			uint32_t o = 2;
			while(o < len) {
				int topic_len = (mqtt_msg[o] << 8) | mqtt_msg[o + 1];
				topic_len = std::min(topic_len, int(len - o));
				DOLOG(debug, "MQTT(%s): topic len: %d\n", ms->session_name.c_str(), topic_len);
				std::string topic((const char *)&mqtt_msg[o + 2], topic_len);
				DOLOG(debug, "MQTT(%s): subscribe to topic name: %s\n", ms->session_name.c_str(), topic.c_str());

				register_topic(topic, ms);

				o += 2 + topic_len;
				DOLOG(debug, "MQTT(%s): qos: %d\n", ms->session_name.c_str(), mqtt_msg[o]);
				reply.push_back(2);
				o++;
			}

			reply.at(1) = reply.size() - 2;

			ts->get_stream_target()->send_data(ts, reply.data(), reply.size());
		}
		else if (cmsg == 12) {  // PINGREQ
			DOLOG(debug, "MQTT(%s): PINGREQ\n", ms->session_name.c_str());
			std::vector<uint8_t> reply;
			reply.push_back(13 << 4);  // PINGRESP
			reply.push_back(0);  // no extra data

			ts->get_stream_target()->send_data(ts, reply.data(), reply.size());
		}
		else {
			DOLOG(info, "MQTT(%s): Unexpected command %d received\n", ms->session_name.c_str(), cmsg);
		}

		delete [] mqtt_msg;
	}

	unregister_all_topics(ms);

	DOLOG(info, "MQTT(%s): Thread terminating (and closing session) for %s\n", ms->session_name.c_str(), ms->client_addr.c_str());

	ts->get_stream_target()->end_session(ts);
}

bool mqtt_close_session_1(pstream *const ps, session *const ts)
{
        void *private_data = ts->get_callback_private_data();

	if (private_data) {
		mqtt_session_data *ms = static_cast<mqtt_session_data *>(private_data);

		ms->terminate = true;

		const std::lock_guard<std::mutex> lck(ms->w_lock);
		ms->w_cond.notify_one();
	}

	return true;
}

bool mqtt_close_session_2(pstream *const ps, session *ts)
{
        void *private_data = ts->get_callback_private_data();

	if (private_data) {
		mqtt_session_data *ms = static_cast<mqtt_session_data *>(private_data);

		ms->terminate = true;

		{
			const std::lock_guard<std::mutex> lck(ms->w_lock);
			ms->w_cond.notify_one();
		}

		ms->th->join();
		delete ms->th;

		delete ms;

		ts->set_callback_private_data(nullptr);
	}

	return true;
}

port_handler_t mqtt_get_handler(stats *const s)
{
	port_handler_t tcp_mqtt;

	tcp_mqtt.init             = mqtt_init;
	tcp_mqtt.new_session      = mqtt_new_session;
	tcp_mqtt.new_data         = mqtt_new_data;
	tcp_mqtt.session_closed_1 = mqtt_close_session_1;
	tcp_mqtt.session_closed_2 = mqtt_close_session_2;
	tcp_mqtt.deinit           = mqtt_deinit;
	tcp_mqtt.pd               = nullptr;

	return tcp_mqtt;
}
