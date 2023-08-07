// (C) 2020-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <jansson.h>

#include "application.h"
#include "log.h"
#include "pstream.h"
#include "tcp.h"
#include "types.h"
#include "utils.h"


using namespace std::chrono_literals;

void mynetperf_init()
{
}

void mynetperf_deinit()
{
}

void mynetperf_handle_data(session *const session_in)
{
        mynetperf_session_data *session = dynamic_cast<mynetperf_session_data *>(session_in->get_callback_private_data());

	if (session->state == mynetperf_session_data::mnp_command) {
		const uint8_t *lf = reinterpret_cast<const uint8_t *>(memchr(session->req_data, '\n', session->req_len));

		if (lf) {
			json_error_t err { 0 };
			json_t *command = json_loadb(reinterpret_cast<const char *>(session->req_data), lf - session->req_data, 0, &err);  // -1: lf

			if (!command) {
				DOLOG(ll_info, "mynetperf_handle_data: json decode failed (%s) for \"%s\"\n", err.text, std::string(reinterpret_cast<const char *>(session->req_data), lf - session->req_data).c_str());

				session->terminate = true;
				return;
			}

			json_t *rc1 = json_object_get(command, "block_size");
			json_t *rc2 = json_object_get(command, "mode");

			if (!rc1 || !rc2) {
				DOLOG(ll_info, "mynetperf_handle_data: block_size and/or mode missing\n");
				json_decref(command);
				session->terminate = true;
				return;
			}

			session->block_size = json_integer_value(rc1);

			std::string mode = json_string_value(rc2);

			if (mode == "receive")
				session->state = mynetperf_session_data::mnp_receive;
			else if (mode == "send")
				session->state = mynetperf_session_data::mnp_send;
			else {
				json_decref(command);
				session->terminate = true;
				DOLOG(ll_info, "mynetperf_handle_data: mode invalid\n");
				return;
			}

			std::string reply = "{ \"result\" : \"ok\" }\n";

			session_in->get_stream_target()->send_data(session_in, reinterpret_cast<const uint8_t *>(reply.c_str()), reply.size());

			DOLOG(ll_info, "mynetperf_handle_data: command \"%s\" received for %zu bytes\n", mode.c_str(), size_t(session->block_size));

			json_decref(command);

			free(session->req_data);
			session->req_data = nullptr;

			session->req_len = 0;

			session->data_transferred = 0;

			session->start_ts = get_us();
		}
		else if (session->req_len > 1024 * 1024) {
			free(session->req_data);
			session->req_data = nullptr;

			session->req_len = 0;

			session->terminate = true;
		}
	}

	if (session->state == mynetperf_session_data::mnp_receive) {
		uint64_t now_ts = get_us();

		uint64_t data_left = session->block_size - session->data_transferred;

		DOLOG(ll_debug, "mynetperf_handle_data: transfer (receive) requested for %zu bytes\n", size_t(data_left));

		if (data_left <= session->req_len) {
			int64_t data_keep = session->req_len - data_left;

			if (data_keep > 0)
				memmove(&session->req_data[0], &session->req_data[data_left], data_keep);

			session->data_transferred = 0;
			session->block_size       = 0;

			session->req_len = data_keep;

			std::string reply = myformat("{ \"result\": \"ok\", \"took\": %zu, \"unit\": \"us\" }\n", size_t(now_ts - session->start_ts));

			session_in->get_stream_target()->send_data(session_in, reinterpret_cast<const uint8_t *>(reply.c_str()), reply.size());

			session->state = mynetperf_session_data::mnp_command;

			DOLOG(ll_debug, "mynetperf_handle_data: block receive succeeded\n");
		}
		else {
			session->data_transferred += session->req_len;

			session->req_len = 0;

			free(session->req_data);
			session->req_data = nullptr;
		}
	}

	if (session->state == mynetperf_session_data::mnp_send) {
		uint64_t now_ts = get_us();

		uint64_t data_left = session->block_size - session->data_transferred;

		DOLOG(ll_debug, "mynetperf_handle_data: transfer (send) requested for %zu bytes\n", size_t(data_left));

		const uint64_t max_block_size = 65536;  // largest possible mtu on ethernet? (TODO)

		uint8_t *data = reinterpret_cast<uint8_t *>(malloc(max_block_size));

		while(data_left > 0) {
			uint64_t cur_block_size = std::min(max_block_size, data_left);

			session->data_transferred += cur_block_size;

			data_left -= cur_block_size;

			session_in->get_stream_target()->send_data(session_in, data, cur_block_size);
		}

		free(data);

		std::string reply = myformat("{ \"result\": \"ok\", \"took\": %zu, \"unit\": \"us\" }\n", size_t(now_ts - session->start_ts));

		session_in->get_stream_target()->send_data(session_in, reinterpret_cast<const uint8_t *>(reply.c_str()), reply.size());

		session->state = mynetperf_session_data::mnp_command;

		DOLOG(ll_debug, "mynetperf_handle_data: block transmit succeeded\n");
	}
}

void mynetperf_thread(session *session_in)
{
        set_thread_name("myip-mynetperf");

	DOLOG(ll_info, "mynetperf_thread: starting\n");

        mynetperf_session_data *session = dynamic_cast<mynetperf_session_data *>(session_in->get_callback_private_data());

        std::unique_lock<std::mutex> lck(session->r_lock);

        for(;session->terminate == false;) {
                if (session->req_data != nullptr)
			mynetperf_handle_data(session_in);

                session->r_cond.wait_for(lck, 500ms);
        }

	DOLOG(ll_info, "mynetperf_thread: terminates\n");
}

bool mynetperf_new_session(pstream *const ps, session *const session)
{
	DOLOG(ll_info, "mynetperf_new_session\n");

        mynetperf_session_data *ts = new mynetperf_session_data();
        ts->req_data = nullptr;
        ts->req_len  = 0;

	ts->buffer     = nullptr;
	ts->block_size = 0;
	ts->state      = mynetperf_session_data::mnp_command;
	//
	ts->data_transferred = 0;

        any_addr src_addr = session->get_their_addr();
        ts->client_addr   = src_addr.to_str();

        session->set_callback_private_data(ts);

        ts->th = new std::thread(mynetperf_thread, session);

        return true;
}

bool mynetperf_new_data(pstream *const ps, session *const session_in, buffer_in data)
{
        if (!session_in) {
                DOLOG(ll_info, "MYNETPERF: Data for a non-existing session\n");

                return false;
        }

        mynetperf_session_data *session = dynamic_cast<mynetperf_session_data *>(session_in->get_callback_private_data());

        int data_len = data.get_n_bytes_left();
	DOLOG(ll_debug, "mynetperf_new_data: %d bytes\n", data_len);

        if (data_len == 0) {
                DOLOG(ll_debug, "MYNETPERF: client closed session\n");

                return true;
        }

        const std::lock_guard<std::mutex> lck(session->r_lock);

        session->req_data = reinterpret_cast<uint8_t *>(realloc(session->req_data, session->req_len + data_len));

        memcpy(&session->req_data[session->req_len], data.get_bytes(data_len), data_len);
        session->req_len += data_len;

        session->r_cond.notify_one();

        return true;
}

bool mynetperf_session_closed_1(pstream *const ps, session *const session)
{
	return true;
}

bool mynetperf_session_closed_2(pstream *const ps, session *const session)
{
	session_data *sd = session->get_callback_private_data();

	if (sd) {
		mynetperf_session_data *esd = dynamic_cast<mynetperf_session_data *>(sd);

		esd->terminate = true;

		esd->th->join();
		delete esd->th;
		esd->th = nullptr;

		free(esd->req_data);

		delete esd;

		session->set_callback_private_data(nullptr);
	}

	return true;
}

port_handler_t mynetperf_get_handler()
{
	port_handler_t meta { 0 };

	meta.init             = mynetperf_init;
	meta.deinit           = mynetperf_deinit;
	meta.new_session      = mynetperf_new_session;
	meta.new_data         = mynetperf_new_data;
	meta.session_closed_1 = mynetperf_session_closed_1;
	meta.session_closed_2 = mynetperf_session_closed_2;
	
	return meta;
}
