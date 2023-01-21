// (C) 2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>

#include "buffer_out.h"
#include "fifo.h"
#include "stats.h"


class dns;
class tcp;

typedef enum { mc_resolve, mc_setup, mc_connect, mc_setup_mqtt_session_connect_req, mc_setup_mqtt_session_connect_ackwait, mc_setup_mqtt_subscribe, mc_running, mc_disconnect } mc_state_t;

class mqtt_client
{
private:
	tcp        *const t         { nullptr };
	dns        *const dns_      { nullptr };

	const std::string mqtt_host;
	const int         mqtt_port;

	stats      *const s         { nullptr };

	std::thread      *th        { nullptr };
	std::atomic_bool  stop_flag { false   };

	std::atomic<mc_state_t> state     { mc_resolve };

	std::mutex              lock;
	std::condition_variable cv;
	uint8_t                *data_in   { nullptr };
	size_t                  n_data_in { 0       };

	uint16_t                msg_id    { 0       };
	std::map<std::string, fifo<std::string> *> topics;
	int                     src_port  { 0       };

	bool read(uint8_t *target, size_t n);

	std::optional<uint32_t> get_variable_length();
	void put_variable_length(uint32_t v, buffer_out *const p);

	buffer_out create_subscribe_message(const std::optional<std::string> & topic);
	buffer_out create_unsubscribe_message(const std::string & topic);

	bool process_command(const uint8_t cmd, const uint8_t *const payload, const size_t pl_len);

public:
	mqtt_client(tcp *const t, dns *const dns_, const std::string & mqtt_host, const int mqtt_port, stats *const s);
	virtual ~mqtt_client();

	void new_data(const buffer_in & data);
	void close_session();

	fifo<std::string> * subscribe(const std::string & topic);

	void unsubscribe(const std::string & topic, fifo<std::string> *const msgs);

	void operator()();
};
