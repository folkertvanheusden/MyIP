// (C) 2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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


using namespace std::chrono_literals;

void irc_init()
{
}

void irc_deinit()
{
}

static void process_line(const std::string & line)
{
	// TODO
}

void irc_thread(session *t_s)
{
        set_thread_name("myip-irc");

        irc_session_data *ts = dynamic_cast<irc_session_data *>(t_s->get_callback_private_data());

        for(;ts->terminate == false;) {
		std::unique_lock<std::mutex> lck(ts->r_lock);

		const char *start = reinterpret_cast<const char *>(ts->req_data);

		if (start) {
			const char *crlf = strnstr(start, "\r\n", ts->req_len);

			if (crlf) {
				process_line(std::string(start, crlf - start));

				size_t n_left = ts->req_len - (crlf + 2 - start);

				if (n_left) {
					memmove(ts->req_data, crlf + 2, n_left);
					ts->req_len -= n_left;
				}
				else {
					ts->req_len = 0;
				}
			}
		}

		ts->r_cond.wait_for(lck, 500ms);
	}
}

bool irc_new_session(pstream *const t, session *t_s)
{
	irc_session_data *ts = new irc_session_data();
	ts->req_data = nullptr;
	ts->req_len  = 0;

	any_addr src_addr = t_s->get_their_addr();
	ts->client_addr   = src_addr.to_str();

	t_s->set_callback_private_data(ts);

	ts->th = new std::thread(irc_thread, t_s);

	return true;
}

bool irc_new_data(pstream *ps, session *ts, buffer_in b)
{
	if (!ts) {
		DOLOG(ll_info, "IRC: Data for a non-existing session\n");

		return false;
	}

	irc_session_data *t_s = dynamic_cast<irc_session_data *>(ts->get_callback_private_data());

	int data_len = b.get_n_bytes_left();

	if (data_len == 0) {
		DOLOG(ll_debug, "IRC: client closed session\n");

		return true;
	}

	const std::lock_guard<std::mutex> lck(t_s->r_lock);

	t_s->req_data = reinterpret_cast<uint8_t *>(realloc(t_s->req_data, t_s->req_len + data_len + 1));

	memcpy(&t_s->req_data[t_s->req_len], b.get_bytes(data_len), data_len);
	t_s->req_len += data_len;
	t_s->req_data[t_s->req_len] = 0x00;

	t_s->r_cond.notify_one();

	return true;
}

bool irc_close_session_1(pstream *const ps, session *ts)
{
	return true;
}

bool irc_close_session_2(pstream *const ps, session *ts)
{
	session_data *sd = ts->get_callback_private_data();

	if (sd) {
		irc_session_data *nsd = dynamic_cast<irc_session_data *>(sd);

		nsd->terminate = true;

		nsd->th->join();
		delete nsd->th;
		nsd->th = nullptr;

		free(nsd->req_data);

		delete nsd;

		ts->set_callback_private_data(nullptr);
	}

	return true;
}

port_handler_t irc_get_handler(stats *const s)
{
	port_handler_t tcp_irc;

	tcp_irc.init             = irc_init;
	tcp_irc.new_session      = irc_new_session;
	tcp_irc.new_data         = irc_new_data;
	tcp_irc.session_closed_1 = irc_close_session_1;
	tcp_irc.session_closed_2 = irc_close_session_2;
	tcp_irc.deinit           = irc_deinit;

	tcp_irc.pd               = nullptr;

	return tcp_irc;
}
