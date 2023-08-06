// (C) 2020-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include "application.h"
#include "log.h"
#include "pstream.h"
#include "types.h"
#include "utils.h"


using namespace std::chrono_literals;

void echo_init()
{
}

void echo_deinit()
{
}

void echo_thread(session *session_in)
{
        set_thread_name("myip-echo");

        echo_session_data *session = dynamic_cast<echo_session_data *>(session_in->get_callback_private_data());

        std::unique_lock<std::mutex> lck(session->r_lock);

        for(;session->terminate == false;) {
                if (lck.owns_lock()) {
                        if (session->req_data) {
				session_in->get_stream_target()->send_data(session_in, session->req_data, session->req_len);

				free(session->req_data);

				session->req_data = nullptr;
				session->req_len  = 0;
                        }
                }

                session->r_cond.wait_for(lck, 500ms);
        }
}


bool echo_new_session(pstream *const ps, session *const session)
{
        echo_session_data *ts = new echo_session_data();
        ts->req_data = nullptr;
        ts->req_len  = 0;

        any_addr src_addr = session->get_their_addr();
        ts->client_addr   = src_addr.to_str();

        session->set_callback_private_data(ts);

        ts->th = new std::thread(echo_thread, session);

        return true;
}

bool echo_new_data(pstream *const ps, session *const session_in, buffer_in data)
{
        if (!session_in) {
                DOLOG(ll_info, "ECHO: Data for a non-existing session\n");

                return false;
        }

        echo_session_data *session = dynamic_cast<echo_session_data *>(session_in->get_callback_private_data());

        int data_len = data.get_n_bytes_left();

        if (data_len == 0) {
                DOLOG(ll_debug, "ECHO: client closed session\n");

                return true;
        }

        const std::lock_guard<std::mutex> lck(session->r_lock);

        session->req_data = reinterpret_cast<uint8_t *>(realloc(session->req_data, session->req_len + data_len + 1));

        memcpy(&session->req_data[session->req_len], data.get_bytes(data_len), data_len);
        session->req_len += data_len;
        session->req_data[session->req_len] = 0x00;

        session->r_cond.notify_one();

        return true;
}

bool echo_session_closed_1(pstream *const ps, session *const session)
{
	return true;
}

bool echo_session_closed_2(pstream *const ps, session *const session)
{
	session_data *sd = session->get_callback_private_data();

	if (sd) {
		echo_session_data *esd = dynamic_cast<echo_session_data *>(sd);

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

port_handler_t echo_get_handler()
{
	port_handler_t meta { 0 };

	meta.init             = echo_init;
	meta.deinit           = echo_deinit;
	meta.new_session      = echo_new_session;
	meta.new_data         = echo_new_data;
	meta.session_closed_1 = echo_session_closed_1;
	meta.session_closed_2 = echo_session_closed_2;
	
	return meta;
}
