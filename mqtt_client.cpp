// (C) 2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <thread>

#include "buffer_out.h"
#include "dns.h"
#include "log.h"
#include "mqtt_client.h"
#include "pstream.h"
#include "tcp.h"
#include "utils.h"


static bool mqtt_new_data(pstream *const ps, session *const s, buffer_in data)
{
	mqtt_client_session_data *t_s = dynamic_cast<mqtt_client_session_data *>(s->get_callback_private_data());

	t_s->mc->new_data(data);

	return true;
}

static bool mqtt_session_closed_2(pstream *const ps, session *const s)
{
	mqtt_client_session_data *t_s = dynamic_cast<mqtt_client_session_data *>(s->get_callback_private_data());

	t_s->mc->close_session();

	return true;
}

mqtt_client::mqtt_client(tcp *const t, dns *const dns_, const std::string & mqtt_host, const int mqtt_port, stats *const s) :
	t(t),
	dns_(dns_),
	mqtt_host(mqtt_host),
	mqtt_port(mqtt_port),
	s(s)
{
	th = new std::thread(std::ref(*this));
}

mqtt_client::~mqtt_client()
{
	stop_flag = true;

	th->join();
	delete th;
}

void mqtt_client::new_data(const buffer_in & data)
{
	size_t new_n = data.get_n_bytes_left();

	std::unique_lock<std::mutex> lck(lock);

	data_in = reinterpret_cast<uint8_t *>(realloc(data_in, n_data_in + new_n));
	// TODO: error checking

	memcpy(&data_in[n_data_in], data.get_bytes(new_n), new_n);

	cv.notify_all();
}

void mqtt_client::close_session()
{
	state = mc_disconnect;
}

bool mqtt_client::read(uint8_t *target, size_t n)
{
	std::unique_lock<std::mutex> lck(lock);

	while(n) {
		if (n_data_in) {
			size_t cur_n = std::min(n, n_data_in);

			memcpy(target, data_in, cur_n);

			size_t n_left = n_data_in - cur_n;
			if (n_left) {
				memmove(&data_in[0], &data_in[cur_n], n_left);

				n_data_in -= cur_n;
			}

			target += cur_n;
			n      -= cur_n;
		}

		cv.wait(lck);  // TODO timeout
	}

	return true;
}

std::optional<uint32_t> mqtt_client::get_variable_length()
{
	uint32_t v   = 0;

	for(;;) {
		uint8_t byte = 0;

		if (read(&byte, 1) == false)
			return { };

		v <<= 7;

		if ((byte & 128) == 0) {
			v |= byte;

			return { v };
		}

		v |= byte & 127;
	}

	return { };
}

void mqtt_client::put_variable_length(uint32_t v, buffer_out *const p)
{
	int bits = determine_value_size(v);

	while(bits > 0) {
		uint8_t cur = v & 127;

		if (bits > 7)
			p->add_net_byte(cur | 128), bits -= 7, v >>= 7;
		else
			p->add_net_byte(cur), bits = 0;
	}
}

buffer_out mqtt_client::create_subscribe_message(const std::optional<std::string> & topic)
{
	buffer_out b_header;
	b_header.add_net_byte(0x80);  // SUBSCRIBE

	buffer_out b_payload;
	b_payload.add_net_byte(msg_id >> 8);  // msg id
	b_payload.add_net_byte(msg_id);
	msg_id++;

	if (topic.has_value()) {
		b_payload.add_net_byte(topic.value().size() >> 8);  // topic name length
		b_payload.add_net_byte(topic.value().size());

		for(auto c : topic.value())
			b_payload.add_net_byte(c);

		b_payload.add_net_byte(1);  // QOS
	}
	else {
		std::unique_lock<std::mutex> lck(lock);

		for(auto topic : topics) {
			b_payload.add_net_byte(topic.first.size() >> 8);  // topic name length
			b_payload.add_net_byte(topic.first.size());

			for(auto c : topic.first)
				b_payload.add_net_byte(c);

			b_payload.add_net_byte(1);  // QOS
		}
	}

	put_variable_length(b_payload.get_size(), &b_header);

	return b_header;
}

bool mqtt_client::process_command(const uint8_t cmd, const uint8_t *const payload, const size_t pl_len)
{
	if (cmd == 0x30 && pl_len > 8) {  // PUBLISH
		size_t topic_name_len = (payload[0] << 8) | payload[1];

		if (topic_name_len + 8 > pl_len) {
			DOLOG(ll_debug, "mqtt_client: message malformed\n");
			return false;
		}
		
		std::string topic_name(reinterpret_cast<const char *>(&payload[2]), topic_name_len);

		// msg id @ &payload[2 + topic_name_len]

		// data @ &payload[2 + topic_name_len + 2]

		{
			std::unique_lock<std::mutex> lck(lock);

			auto it = topics.find(topic_name);
			if (it == topics.end()) {
				DOLOG(ll_debug, "mqtt_client: topic \"%s\" not known\n", topic_name.c_str());

				return false;
			}

			it->second->try_put(std::string(reinterpret_cast<const char *>(&payload[2 + topic_name_len + 2]), pl_len - (2 + topic_name_len + 2)));
		}

		// send ACK
		buffer_out b;
		b.add_net_byte(0x40);  // PUBACK
		b.add_net_byte(0x02);
		b.add_net_byte(payload[2 + topic_name_len + 0]);
		b.add_net_byte(payload[2 + topic_name_len + 1]);

		if (t->client_session_send_data(src_port, b.get_content(), b.get_size()) == false) {
			DOLOG(ll_debug, "mqtt_client: problem transmitting\n");

			return false;
		}

		return true;
	}
	else {
		DOLOG(ll_debug, "mqtt_client: ignoring %02x\n", cmd);

		return true;
	}

	return false;
}

void mqtt_client::operator()()
{
	set_thread_name("myip-mqtt-client");

	std::optional<any_addr> addr;

	while(!stop_flag) {
		if (state == mc_resolve) {
			DOLOG(ll_debug, "mqtt_client state: resolve\n");

			addr = dns_->query(mqtt_host, 2500);

			if (addr.has_value()) {
				DOLOG(ll_debug, "mqtt_client: address of \"%s\" is %s\n", mqtt_host.c_str(), addr.value().to_str().c_str());

				state = mc_setup;
			}
		}

		if (state == mc_setup) {
			DOLOG(ll_debug, "mqtt_client state: setup\n");

			mqtt_client_session_data *session_data = new mqtt_client_session_data;
			session_data->mc = this;

			src_port = t->allocate_client_session(mqtt_new_data, mqtt_session_closed_2, addr.value(), mqtt_port, session_data);

			DOLOG(ll_debug, "mqtt_client: using source port %d for %s:%d\n", src_port, mqtt_host.c_str(), mqtt_port);

			state     = mc_connect;

			free(data_in);
			data_in   = nullptr;

			n_data_in = 0;
		}

		if (state == mc_connect) {
			DOLOG(ll_debug, "mqtt_client state: connect\n");

			if (t->wait_for_client_connected_state(src_port))
				state = mc_setup_mqtt_session_connect_req;
			else {
				DOLOG(ll_debug, "mqtt_client: session setup failed (source port %d)\n", src_port);

				state = mc_disconnect;
			}
		}

		if (state == mc_setup_mqtt_session_connect_req) {
			DOLOG(ll_debug, "mqtt_client state: session_connect_req\n");

			char id[17];
			snprintf(id, sizeof id, "%016x", rand());

			buffer_out b;
			b.add_net_byte(0x10);  // CONNECT
			b.add_net_byte(12 + 2 + 16);  // msg length

			b.add_net_byte(0);  // protocol name length + name
			b.add_net_byte(6);
			b.add_net_byte('M');
			b.add_net_byte('Q');
			b.add_net_byte('I');
			b.add_net_byte('s');
			b.add_net_byte('d');
			b.add_net_byte('p');

			b.add_net_byte(3);  // protocol version

			b.add_net_byte(0x02);  // flags

			b.add_net_byte(0x00);  // keep alive timer
			b.add_net_byte(0x0a);

			b.add_net_byte(0);  // client id length
			b.add_net_byte(16);
			for(int i=0; i<16; i++)  // client id
				b.add_net_byte(id[i]);

			if (t->client_session_send_data(src_port, b.get_content(), b.get_size()) == false)
				state = mc_disconnect;
			else
				state = mc_setup_mqtt_session_connect_ackwait;
		}

		if (state == mc_setup_mqtt_session_connect_ackwait) {
			DOLOG(ll_debug, "mqtt_client state: session_connect_ackwait\n");

			uint8_t buffer[4];

			if (read(buffer, sizeof buffer) == false) {
				DOLOG(ll_debug, "mqtt_client: connack reply read failed\n");

				state = mc_disconnect;
			}
			else if (buffer[0] == 0x20 && buffer[3] == 0x00)
				state = mc_setup_mqtt_subscribe;
			else {
				DOLOG(ll_debug, "mqtt_client: connack reply unexpected contents\n");

				state = mc_disconnect;
			}
		}

		if (state == mc_setup_mqtt_subscribe) {
			DOLOG(ll_debug, "mqtt_client state: session_connect_subscribe\n");

			buffer_out b = create_subscribe_message({ });

			if (t->client_session_send_data(src_port, b.get_content(), b.get_size()) == false)
				state = mc_disconnect;
			else
				state = mc_running;
		}

		if (state == mc_running) {
			DOLOG(ll_debug, "mqtt_client state: running\n");

			uint8_t  cmd    = 0;
			uint8_t *pl     = nullptr;
			uint32_t pl_len = 0;

			if (read(&cmd, 1)) {
				auto len = get_variable_length();

				if (len.has_value())
					pl_len = len.value();
				else
					state = mc_disconnect;
			}

			if (state == mc_running && pl_len) {
				pl = new uint8_t[pl_len];

				if (pl == nullptr || read(pl, pl_len) == false)
					state = mc_disconnect;
			}

			if (state == mc_running) {
				if (process_command(cmd, pl, pl_len) == false)
					state = mc_disconnect;
			}

			delete [] pl;
		}

		if (state == mc_disconnect) {
			DOLOG(ll_debug, "mqtt_client state: disconnect\n");

			t->close_client_session(src_port);

			state = mc_resolve;
		}
	}

	DOLOG(ll_info, "mqtt-client: thread terminating\n");
}

fifo<std::string> * mqtt_client::subscribe(const std::string & topic)
{
	buffer_out b = create_subscribe_message(topic);

	if (t->client_session_send_data(src_port, b.get_content(), b.get_size()) == false)
		return nullptr;

	auto f = new fifo<std::string>(s, "mqtt-" + topic, 256);

	std::unique_lock<std::mutex> lck(lock);

	topics.insert({ topic, f });

	return f;
}

buffer_out mqtt_client::create_unsubscribe_message(const std::string & topic)
{
	buffer_out b_header;
	b_header.add_net_byte(0xa0);  // UNSUBSCRIBE

	buffer_out b_payload;
	b_payload.add_net_byte(msg_id >> 8);  // msg id
	b_payload.add_net_byte(msg_id);
	msg_id++;

	b_payload.add_net_byte(topic.size() >> 8);  // topic name length
	b_payload.add_net_byte(topic.size());

	for(auto c : topic)
		b_payload.add_net_byte(c);

	put_variable_length(b_payload.get_size(), &b_header);

	return b_header;
}

void mqtt_client::unsubscribe(const std::string & topic, fifo<std::string> *const msgs)
{
	delete msgs;

	buffer_out b = create_unsubscribe_message(topic);

	if (t->client_session_send_data(src_port, b.get_content(), b.get_size())) {
		std::unique_lock<std::mutex> lck(lock);

		topics.erase(topic);
	}
}
