#pragma once

#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

class private_data
{
public:
	private_data() { }
};

class http_private_data : public private_data
{
public:
	std::string logfile, web_root;
};

class session_data
{
public:
	session_data() { }

	std::string client_addr;
};

class http_session_data : public session_data
{
public:
	char *req_data;
	size_t req_len;
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
	char *buffer;
	size_t buffer_size;

	vnc_state_t state;

	uint8_t depth;  // 'bits per pixel' really

	std::thread *th;

	std::queue<vnc_thread_work_t *> wq;
        std::condition_variable w_cond;
        mutable std::mutex w_lock;
};
