// (C) 2020-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>
#include <zlib.h>

#include "mqtt_client.h"
#include "packet.h"
#include "stats.h"


class private_data
{
public:
	private_data() { }
	virtual ~private_data() = default;
};

class http_private_data : public private_data
{
public:
	std::string logfile;
	std::string web_root;
	bool        is_https { false };
	stats      *s        { nullptr };
	std::string private_key;
	std::string certificate;
	std::string php_cgi;

	uint64_t *http_requests { nullptr };
	uint64_t *http_r_200 { nullptr };
	uint64_t *http_r_404 { nullptr };
	uint64_t *http_r_500 { nullptr };
	uint64_t *http_r_err { nullptr };
};

class nrpe_private_data : public private_data
{
public:
	stats    *s             { nullptr };

	uint64_t *nrpe_requests { nullptr };
	uint64_t *nrpe_r_err    { nullptr };
};

class vnc_private_data : public private_data
{
public:
	uint64_t *vnc_requests { nullptr };
	uint64_t *vnc_err      { nullptr };
	uint64_t *vnc_duration { nullptr };
};

class mqtt_private_data : public private_data
{
};

class session_data
{
public:
	session_data() { }
	virtual ~session_data() = default;

	std::string client_addr;
};

class http_session_data : public session_data
{
public:
	~http_session_data() {
		if (th) {
			terminate = true;

			th->join();
			delete th;
		}
	}

	std::thread     *th        { nullptr };
	std::atomic_bool terminate { false   };

        std::condition_variable r_cond;
        mutable std::mutex      r_lock;

	char *req_data { nullptr };
	size_t req_len { 0       };
};

class nrpe_session_data : public session_data
{
public:
	~nrpe_session_data() {
		if (th) {
			terminate = true;

			th->join();
			delete th;
		}
	}

	std::thread     *th        { nullptr };
	std::atomic_bool terminate { false   };

        std::condition_variable r_cond;
        mutable std::mutex      r_lock;

	uint8_t *req_data { nullptr };
	size_t   req_len  { 0       };
};

typedef struct _vnc_thread_work_t_ {
	// nullptr if update requested
	packet *pkt;

	char *data;
	size_t data_len;

	_vnc_thread_work_t_() {
		pkt = nullptr;
		data = nullptr;
		data_len = 0;
	}
} vnc_thread_work_t;

typedef enum {  vs_initial_handshake_server_send = 0,
		vs_initial_handshake_client_resp,
		vs_security_handshake_server,
		vs_security_handshake_client_resp,
		vs_client_init,
		vs_server_init,
		vs_running_waiting_cmd,
		vs_running_waiting_data,
		vs_running_waiting_data_extra,
		vs_running_waiting_data_ignore,
		vs_terminate
} vnc_state_t;

class vnc_session_data : public session_data
{
public:
	char  *buffer      { nullptr };
	size_t buffer_size { 0       };

	vnc_state_t state  { vs_initial_handshake_server_send };

	uint8_t      depth { 8       };  // 'bits per pixel' really

	std::thread *th    { nullptr };

	time_t       start { 0       };

	std::queue<vnc_thread_work_t *> wq;
        std::condition_variable         w_cond;
        mutable std::mutex              w_lock;

	uint32_t          prev_zsize { 0       };
	vnc_private_data *vpd        { nullptr };

	z_stream          strm       { 0       };

	mqtt_client      *mc         { nullptr };
	fifo<std::string> *mc_data   { nullptr };
};

class mqtt_session_data : public session_data
{
public:
	std::thread *th { nullptr };

	uint8_t *data { nullptr };
	size_t data_len { 0 };
        std::condition_variable w_cond;
        mutable std::mutex w_lock;
	std::vector<std::pair<uint8_t *, size_t> > msgs_out;

	std::string session_name;

	std::atomic_bool terminate { false };
};

class mqtt_client;

class mqtt_client_session_data : public session_data
{
public:
	mqtt_client *mc;
};

class socks_session_data : public session_data
{
private:
	const int fd { -1 };

public:
	socks_session_data(const int fd) : fd(fd) { }
	~socks_session_data() { close(fd); }

	int get_fd() const { return fd; }
};

class irc_session_data : public session_data
{
public:
	std::thread     *th        { nullptr };
	std::atomic_bool terminate { false   };

        std::condition_variable r_cond;
        mutable std::mutex      r_lock;

	uint8_t *req_data { nullptr };
	size_t   req_len  { 0       };

	std::string nick;
};
