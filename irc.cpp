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


using namespace std::chrono_literals;

class person
{
public:
	std::string           real_name;
	std::set<std::string> channels;
	session              *tcp_session { nullptr };
};

static std::map<std::string, person> nicknames;
static std::mutex nicknames_lock;

static std::map<std::string, std::string> topicnames;
static std::mutex topicnames_lock;

void irc_init()
{
}

void irc_deinit()
{
}

// I.S.: Internet Session
typedef enum { IS_wait_nick, IS_wait_user, IS_running, IS_disconnect } irc_state_t;

static void process_line(session *const tcp_session, irc_state_t *const is, const std::string & line)
{
	if (line.empty())
		return;

	std::vector<std::string> parts = split(line, " ");

	if (parts.size() == 0)
		return;

	irc_session_data *isd = dynamic_cast<irc_session_data *>(tcp_session->get_callback_private_data());

	if (*is == IS_wait_nick) {
		if (parts.at(0) == "NICK" && parts.size() == 2) {  // ignoring hop count
			// nick must be unique
			auto nick = str_tolower(parts.at(1));

			std::unique_lock<std::mutex> lck(nicknames_lock);

			auto it   = nicknames.find(nick);
			if (it == nicknames.end()) {
				person p;

				p.tcp_session = tcp_session;

				nicknames.insert({ nick, p });

				lck.unlock();

				isd->nick        = nick;

				*is = IS_wait_user;
			}
			else {
				lck.unlock();

				std::string error = ": 433 * " + nick + " :Nickname is already in use.";

				if (tcp_session->get_stream_target()->send_data(tcp_session, reinterpret_cast<const uint8_t *>(error.c_str()), error.size()) == false)
					*is = IS_disconnect;
			}
		}
		else {
			std::string error = ": 421 * :Something is not right.";

			if (tcp_session->get_stream_target()->send_data(tcp_session, reinterpret_cast<const uint8_t *>(error.c_str()), error.size()) == false)
				*is = IS_disconnect;
		}
	}
	else if (*is == IS_wait_user) {
		if (parts.at(0) == "USER" && parts.size() >= 5) {
			std::unique_lock<std::mutex> lck(nicknames_lock);

			auto it = nicknames.find(isd->nick);

			if (it == nicknames.end()) {
				lck.unlock();

				std::string error = ": 401 * :What is your nick?";

				if (tcp_session->get_stream_target()->send_data(tcp_session, reinterpret_cast<const uint8_t *>(error.c_str()), error.size()) == false)
					*is = IS_disconnect;
			}
			else {
				auto rn_offset = line.find(":");
				auto real_name = rn_offset == std::string::npos ? "" : line.substr(rn_offset + 1);

				it->second.real_name = real_name;

				lck.unlock();

				isd->username  = parts.at(1);

				*is = IS_running;

				std::vector<std::string> welcome {
					": 001 " + isd->nick + " :Welcome",
					": 002 " + isd->nick + " :Your host runs MyIP",
					": 003 " + isd->nick + " :003",
					": 004 " + isd->nick + " ",
					": 005 " + isd->nick + " :",
					": 005 " + isd->nick + " :",
					": 251 " + isd->nick + " :",
					": 252 " + isd->nick + " 0 :operator(s) online",
					": 253 " + isd->nick + " 0 :unknown connections",
					": 254 " + isd->nick + " 0 :channels formed",
					": 255 " + isd->nick + " :I have 0 clients and 1 server",
					": 265 " + isd->nick + " :Current local users: 0  Max: 0",
					": 266 " + isd->nick + " :Current global users: 0  Max: 0",
					": 375 " + isd->nick + " :message of the day",
					": 372 " + isd->nick + " :",
					": 376 " + isd->nick + " :End of message of the day."
				};

				for(auto & line : welcome) {
					if (tcp_session->get_stream_target()->send_data(tcp_session, reinterpret_cast<const uint8_t *>(line.c_str()), line.size()) == false) {
						*is = IS_disconnect;
						break;
					}
				}
			}
		}
	}
	else if (*is == IS_running) {
		if (parts.at(0) == "JOIN" && parts.size() >= 2) {
			auto channels = split(parts.at(1), ",");

			std::unique_lock<std::mutex> lck(nicknames_lock);

			auto it = nicknames.find(isd->nick);

			for(auto & channel : channels)
				it->second.channels.insert(str_tolower(channel));
		}
		else if (parts.at(0) == "PART" && parts.size() >= 2) {
			auto channels = split(parts.at(1), ",");

			std::unique_lock<std::mutex> lck(nicknames_lock);

			auto it = nicknames.find(isd->nick);

			for(auto & channel : channels)
				it->second.channels.erase(str_tolower(channel));
		}
		else if ((parts.at(0) == "PRIVMSG" || parts.at(0) == "NOTICE") && parts.size() >= 2) {
			auto target = str_tolower(parts.at(1));

			std::unique_lock<std::mutex> lck(nicknames_lock);

			std::string line_out = ":" + isd->nick + "!" + isd->username + "@" + tcp_session->get_their_addr().to_str() + " " + line;

			for(auto & nick : nicknames) {
				if (nick.second.channels.find(target) != nick.second.channels.end() || target == nick.first)
					nick.second.tcp_session->get_stream_target()->send_data(nick.second.tcp_session, reinterpret_cast<const uint8_t *>(line_out.c_str()), line_out.size());
			}
		}
		// TODO
		else {
			std::string error = ": 421 * :Unknown command.";

			if (tcp_session->get_stream_target()->send_data(tcp_session, reinterpret_cast<const uint8_t *>(error.c_str()), error.size()) == false)
				*is = IS_disconnect;
		}
	}
	else {
		std::string error = ": 421 * :Internal error.";

		tcp_session->get_stream_target()->send_data(tcp_session, reinterpret_cast<const uint8_t *>(error.c_str()), error.size());

		*is = IS_disconnect;
	}
}

void irc_thread(session *const tcp_session)
{
        set_thread_name("myip-irc");

        irc_session_data *ts = dynamic_cast<irc_session_data *>(tcp_session->get_callback_private_data());

	irc_state_t is = IS_wait_nick;

        for(;ts->terminate == false && is != IS_disconnect;) {
		std::unique_lock<std::mutex> lck(ts->r_lock);

		const char *start = reinterpret_cast<const char *>(ts->req_data);

		if (start) {
			const char *crlf = strnstr(start, "\r\n", ts->req_len);

			if (crlf) {
				process_line(tcp_session, &is, std::string(start, crlf - start));

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

		if (is != IS_disconnect)
			ts->r_cond.wait_for(lck, 500ms);
	}

	tcp_session->get_stream_target()->end_session(tcp_session);
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
		DOLOG(ll_info, "IRC: data for a non-existing session\n");

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
