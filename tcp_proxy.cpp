// (C) 2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <errno.h>
#include <map>
#include <mutex>
#include <set>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <thread>

#include "hash.h"
#include "ipv4.h"
#include "log.h"
#include "stats_tracker.h"
#include "stats_utils.h"
#include "str.h"
#include "tcp.h"
#include "types.h"
#include "utils.h"


void tcp_proxy_init()
{
}

void tcp_proxy_deinit()
{
}

static bool new_data_client(pstream *const ps, session *const s, buffer_in data)
{
	tcp *t = reinterpret_cast<tcp *>(ps);

	int n = data.get_n_bytes_left();

	return t->send_data(s, data.get_bytes(n), n);
}

static bool session_closed_2_client(pstream *const ps, session *const s)
{
        tcp_proxy_session_data *tpsd = dynamic_cast<tcp_proxy_session_data *>(s->get_callback_private_data());

	tpsd->terminate = true;

	return true;
}

void tcp_proxy_thread(session *const tcp_session)
{
        set_thread_name("myip-tp");

        tcp_proxy_session_data *tpsd = dynamic_cast<tcp_proxy_session_data *>(tcp_session->get_callback_private_data());
	tcp_proxy_private_data *tppd = dynamic_cast<tcp_proxy_private_data *>(tcp_session->get_application_private_data());

	tcp *t = reinterpret_cast<tcp *>(tcp_session->get_stream_target());

	tpsd->client_port = t->allocate_client_session(new_data_client, session_closed_2_client, tppd->dest_ip, tppd->dest_port, tpsd);

	if (t->wait_for_client_connected_state(tpsd->client_port)) {
		while(tpsd->terminate == false)
			usleep(101000);  // TODO: replace by condition variable
	}

	t->close_client_session(tpsd->client_port);

	t->end_session(tcp_session);
}

bool tcp_proxy_new_session(pstream *const t, session *t_s)
{
	tcp_proxy_session_data *ts = new tcp_proxy_session_data();

	t_s->set_callback_private_data(ts);

	ts->th = new std::thread(tcp_proxy_thread, t_s);

	return true;
}

bool tcp_proxy_new_data(pstream *ps, session *ts, buffer_in b)
{
	if (!ts) {
		DOLOG(ll_info, "TCP-proxy: data for a non-existing session\n");

		return false;
	}

	int data_len = b.get_n_bytes_left();

	if (data_len == 0) {
		DOLOG(ll_debug, "TCP-proxy: client closed session\n");

		return true;
	}

	tcp_proxy_private_data *tppd = dynamic_cast<tcp_proxy_private_data *>(ts->get_application_private_data());

	int n = b.get_n_bytes_left();

	tcp *t = reinterpret_cast<tcp *>(ps);

	return t->client_session_send_data(tppd->dest_port, b.get_bytes(n), n);
}

bool tcp_proxy_close_session_1(pstream *const ps, session *ts)
{
	return true;
}

bool tcp_proxy_close_session_2(pstream *const ps, session *ts)
{
	DOLOG(ll_debug, "TCP-proxy: closing %s\n", ts->to_str().c_str());

	session_data *sd = ts->get_callback_private_data();

	if (sd) {
		tcp_proxy_session_data *nsd = dynamic_cast<tcp_proxy_session_data *>(sd);

		nsd->terminate = true;

		nsd->th->join();
		delete nsd->th;
		nsd->th = nullptr;

		delete nsd;

		ts->set_callback_private_data(nullptr);
	}

	return true;
}

port_handler_t tcp_proxy_get_handler(stats *const s, const any_addr & dest_ip, const int dest_port)
{
	port_handler_t tcp_proxy;

	tcp_proxy.init             = tcp_proxy_init;
	tcp_proxy.new_session      = tcp_proxy_new_session;
	tcp_proxy.new_data         = tcp_proxy_new_data;
	tcp_proxy.session_closed_1 = tcp_proxy_close_session_1;
	tcp_proxy.session_closed_2 = tcp_proxy_close_session_2;
	tcp_proxy.deinit           = tcp_proxy_deinit;

	tcp_proxy_private_data *tpvd = new tcp_proxy_private_data();
	tpvd->dest_ip              = dest_ip;
	tpvd->dest_port            = dest_port;

	tcp_proxy.pd               = tpvd;

	return tcp_proxy;
}
