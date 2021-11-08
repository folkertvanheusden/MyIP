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

static std::mutex topic_lck;
static std::map<const std::string, std::set<mqtt_session_data *> > topic_subscriptions;

static void register_topic(const std::string & topic, mqtt_session_data *const msd)
{
	dolog(debug, "MQTT: Register topic %s for %p\n", topic.c_str(), msd);
	dolog(debug, "MQTT: # topics: %zu\n", topic_subscriptions.size());

	topic_lck.lock();

	auto it = topic_subscriptions.find(topic);
	if (it != topic_subscriptions.end())
		it->second.insert(msd);
	else
		topic_subscriptions.insert({ topic, { msd } });

	dolog(debug, "MQTT: topic %s %zu subscribers\n", topic.c_str(), topic_subscriptions.find(topic)->second.size());

	topic_lck.unlock();
}

static void unregister_topic(const std::string & topic, mqtt_session_data *const msd)
{
	dolog(debug, "MQTT: Unregister topic %s for %p\n", topic.c_str(), msd);
	topic_lck.lock();

	auto it = topic_subscriptions.find(topic);
	if (it != topic_subscriptions.end())
		it->second.erase(msd);

	topic_lck.unlock();
}

static void unregister_all_topics(mqtt_session_data *const msd)
{
	dolog(debug, "MQTT: Unsubscribe %p from all topics\n", msd);

	topic_lck.lock();

	for(auto it : topic_subscriptions)
		it.second.erase(msd);

	topic_lck.unlock();
}

static void publish(const std::string & topic, const uint8_t *const data, const size_t data_len)
{
	dolog(debug, "MQTT: Publishing %d bytes to topic %s\n", data_len, topic.c_str());

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
			dolog(debug, "MQTT: queuing for %p\n", s_it);

			s_it->w_lock.lock();
			s_it->msgs_out.push_back({ duplicate(msg.data(), msg.size()), msg.size() });
			s_it->w_lock.unlock();

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

void mqtt_get_bytes(tcp_session_t *const ts, mqtt_session_data *const ms, uint8_t *const tgt, const size_t n)
{
	std::unique_lock<std::mutex> lck(ms->w_lock);

	for(;!ms->terminate;) {
		dolog(debug, "MQTT: %zu bytes requested, %zu available\n", n, ms->data_len);

		// process outgoing messages
		// they are placed in the queue by publishers
		if (ms->msgs_out.empty() == false) {
			dolog(debug, "MQTT: %zu msgs pending\n", ms->msgs_out.size());

			for (auto it : ms->msgs_out) {
				dolog(debug, "MQTT: sending message of %zu bytes length\n", it.second);

				ts->t->send_data(ts, it.first, it.second, false);
				delete it.first;
			}

			ms->msgs_out.clear();
		}

		// any data?
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

uint8_t mqtt_get_byte(tcp_session_t *const ts, mqtt_session_data *const ms)
{
	uint8_t tgt = 123;

	mqtt_get_bytes(ts, ms, &tgt, 1);

	return tgt;
}

void mqtt_recv_thread(void *ts_in)
{
	set_thread_name("myip-mqtt");

	tcp_session_t *ts = (tcp_session_t *)ts_in;
	mqtt_session_data *ms = dynamic_cast<mqtt_session_data *>(ts->p);

	std::string identifier;

	for(;ms->terminate == false;) {
		uint8_t control = mqtt_get_byte(ts, ms);
		uint32_t len = 0;

		for(;ms->terminate == false;) {
			uint8_t b = mqtt_get_byte(ts, ms);

			len <<= 7;
			len |= b & 127;

			if ((b & 128) == 0)
				break;
		}
		
		uint8_t *mqtt_msg = new uint8_t[len + 1];
		mqtt_get_bytes(ts, ms, mqtt_msg, len);
		mqtt_msg[len] = 0x00;  // e.g. CONNECT msg ends with strings

		uint8_t cmsg = control >> 4;
		//uint8_t cflags = control & 0x0f;

		dolog(debug, "MQTT: control %02x msg %d\n", control, cmsg);

		if (cmsg == 1) {  // CONNECT
			if (len > 12) {  // should be true (variable header + at least 0x00 for identifier)
				identifier = (char *)&mqtt_msg[12];
			}

			dolog(debug, "MQTT: Connect by %s\n", identifier.c_str());

			// send CONNACK
			uint8_t reply[] = { 0x20, 0x02, 0x00 /* reserved */, 0x00 /* accepted */};

			ts->t->send_data(ts, reply, sizeof reply, false);
		}
		else if (cmsg == 3) {  // PUBLISH
			int o = 0;
			int topic_len = std::min((mqtt_msg[0] << 8) | mqtt_msg[1], int(len));
			std::string topic((const char *)&mqtt_msg[2], topic_len);
			o += 2 + topic_len;

			dolog(debug, "MQTT: publish to %s\n", topic.c_str());

			uint16_t msg_id = 0;
			if ((control >> 1) & 3) {
				msg_id = (mqtt_msg[o] << 8) | mqtt_msg[o + 1];
				o += 2;
			}

			uint8_t *payload = &mqtt_msg[o];
			int32_t payload_len = len - o;

			if (payload_len > 0)
				publish(topic, payload, payload_len);

			dolog(debug, "MQTT: %d bytes payload (msg_id %d) for topic %s\n", payload_len, msg_id, topic.c_str());

			std::vector<uint8_t> reply;
			reply.push_back(4 << 4);
			reply.push_back(2);  // remaining length
			reply.push_back(msg_id >> 8);
			reply.push_back(msg_id & 255);

			ts->t->send_data(ts, reply.data(), reply.size(), false);
		}
		else if (cmsg == 8) {  // SUBSCRIBE
			std::vector<uint8_t> reply;
			reply.push_back(0x9 << 4);  // SUBACK

			reply.push_back(0);  // will be length

			uint16_t msg_id = (mqtt_msg[0] << 8) | mqtt_msg[1];
			dolog(debug, "SUBSCRIBE, msg id: %d\n", msg_id);
			reply.push_back(mqtt_msg[0]);
			reply.push_back(mqtt_msg[1]);

			uint32_t o = 2;
			while(o < len) {
				int topic_len = (mqtt_msg[o] << 8) | mqtt_msg[o + 1];
				topic_len = std::min(topic_len, int(len - o));
				dolog(debug, "MQTT: topic len: %d\n", topic_len);
				std::string topic((const char *)&mqtt_msg[o + 2], topic_len);
				dolog(debug, "MQTT: subscribe to topic name: %s\n", topic.c_str());

				register_topic(topic, ms);

				o += 2 + topic_len;
				dolog(debug, "MQTT: qos: %d\n", mqtt_msg[o]);
				reply.push_back(2);
				o++;
			}

			reply.at(1) = reply.size() - 2;

			ts->t->send_data(ts, reply.data(), reply.size(), false);
		}
		else if (cmsg == 12) {  // PINGREQ
			dolog(debug, "MQTT: ping\n");
			std::vector<uint8_t> reply;
			reply.push_back(13 << 4);  // PINGRESP
			reply.push_back(0);  // no extra data

			ts->t->send_data(ts, reply.data(), reply.size(), false);
		}
		else {
			dolog(info, "MQTT: Unexpected command %d received\n", cmsg);
		}

		delete [] mqtt_msg;
	}

	unregister_all_topics(ms);

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
