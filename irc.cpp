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

static std::string local_host;

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

static bool transmit_to_client(session *const tcp_session, const std::string & line)
{
	std::string work = line;

	work.erase(work.begin() + work.find("\r\n"), work.end());

	DOLOG(ll_debug, "irc::transmit_to_client: %s\n", work.c_str());

	return tcp_session->get_stream_target()->send_data(tcp_session, reinterpret_cast<const uint8_t *>(line.c_str()), line.size());
}

static void transmit_to_channel(const std::string & channel, const std::string & msg_line, const std::string & sender_nick)
{
	for(auto & nick : nicknames) {
		if (nick.first == sender_nick)
			continue;

		if (nick.second.channels.find(channel) != nick.second.channels.end() || channel == nick.first)
			transmit_to_client(nick.second.tcp_session, msg_line);
	}
}

static void send_user_for_channel(const std::string & channel, const std::string & nick)
{
	std::string out   = ":" + local_host + " 353 " + nick + " @ " + channel + " :";
	bool        first = true;

	for(auto & nick : nicknames) {
		if (nick.second.channels.find(channel) != nick.second.channels.end()) {
			if (first)
				first = false;
			else
				out += " ";

			out += nick.first;
		}
	}

	out += "\r\n";

	out += ": 366 * " + channel + " :End of /NAMES list.\r\n";

	for(auto & nick : nicknames) {
		if (nick.second.channels.find(channel) != nick.second.channels.end())
			transmit_to_client(nick.second.tcp_session, out);
	}
}

static std::map<std::string, int> get_channel_list()
{
	std::map<std::string, int> channels;

	for(auto nick : nicknames) {
		for(auto ch : nick.second.channels) {
			auto it = channels.find(ch);

			if (it != channels.end())
				it->second++;
			else
				channels.insert({ ch, 1 });
		}
	}
	
	return channels;
}

static std::string get_topic(const std::string & channel)
{
	std::unique_lock<std::mutex> lck(topicnames_lock);

	auto it = topicnames.find(channel);

	if (it == topicnames.end())
		return "";

	return it->second;
}

bool send_topic(session *const tcp_session, const std::string & channel)
{
	std::string topic_line = ": TOPIC " + channel + " :" + get_topic(channel) + "\r\n";

	if (transmit_to_client(tcp_session, topic_line) == false)
		return false;

	return true;
}

static bool process_line(session *const tcp_session, bool *const seen_nick, bool *const seen_user, const std::string & line)
{
	DOLOG(ll_debug, "irc::process_line: |%s|\n", line.c_str());

	if (line.empty())
		return true;

	std::vector<std::string> parts = split(line, " ");

	if (parts.size() == 0)
		return true;

	irc_session_data *isd = dynamic_cast<irc_session_data *>(tcp_session->get_callback_private_data());

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

			isd->nick  = nick;

			*seen_nick = true;
		}
		else {
			lck.unlock();

			std::string error = ": 433 * " + nick + " :Nickname is already in use.\r\n";

			return transmit_to_client(tcp_session, error);
		}

		return true;
	}

	if (parts.at(0) == "USER" && parts.size() >= 5) {
		std::unique_lock<std::mutex> lck(nicknames_lock);

		auto it = nicknames.find(isd->nick);

		if (it == nicknames.end()) {
			lck.unlock();

			std::string error = ": 401 * :What is your nick?\r\n";

			if (transmit_to_client(tcp_session, error) == false)
				return false;
		}
		else {
			auto rn_offset = line.find(":");
			auto real_name = rn_offset == std::string::npos ? "" : line.substr(rn_offset + 1);

			it->second.real_name = real_name;

			size_t user_count    = nicknames.size();

			std::map<std::string, int> channels = get_channel_list();

			lck.unlock();

			isd->username = parts.at(1);

			*seen_user    = true;

			std::string user_count_str = myformat("%zu", user_count);

			std::vector<std::string> welcome {
				": 001 " + isd->nick + " :Welcome\r\n",
				": 002 " + isd->nick + " :Your host runs MyIP\r\n",
				": 003 " + isd->nick + " :\r\n",
				": 004 " + isd->nick + " \r\n",
				": 005 " + isd->nick + " :\r\n",
				": 005 " + isd->nick + " :\r\n",
				": 251 " + isd->nick + " :\r\n",
				": 252 " + isd->nick + " 0 :operator(s) online\r\n",
				": 253 " + isd->nick + " 0 :unknown connections\r\n",
				": 254 " + isd->nick + " " + myformat("%zu", channels.size()) + " :channels formed\r\n",
				": 255 " + isd->nick + " :I have " + user_count_str + " clients and 1 server\r\n",
				": 265 " + isd->nick + " :Current local users: " + user_count_str + " Max: -1\r\n",
				": 266 " + isd->nick + " :Current global users: " + user_count_str + "  Max: -1\r\n",
				": 375 " + isd->nick + " :message of the day\r\n",
				": 372 " + isd->nick + " :\r\n",
				": 376 " + isd->nick + " :End of message of the day.\r\n"
			};

			for(auto & line : welcome) {
				if (transmit_to_client(tcp_session, line) == false)
					return false;
			}
		}

		return true;
	}

	if (*seen_user == false || *seen_nick == false)
		return true;

	if (parts.at(0) == "JOIN" && parts.size() >= 2) {
		auto channels = split(parts.at(1), ",");

		std::unique_lock<std::mutex> lck(nicknames_lock);

		auto it = nicknames.find(isd->nick);

		for(auto & channel : channels) {
			it->second.channels.insert(str_tolower(channel));

			std::string join_line = ":" + isd->nick + "!" + isd->username + "@" + tcp_session->get_their_addr().to_str() + " JOIN " + channel + "\r\n";

			transmit_to_channel(channel, join_line, "___\x03invalid");

			send_user_for_channel(channel, isd->nick);

			if (send_topic(tcp_session, channel) == false)
				return false;
		}

		return true;
	}

	if (parts.at(0) == "PART" && parts.size() >= 2) {
		auto channels = split(parts.at(1), ",");

		std::unique_lock<std::mutex> lck(nicknames_lock);

		auto it = nicknames.find(isd->nick);

		for(auto & channel : channels) {
			it->second.channels.erase(str_tolower(channel));

			std::string part_line = ":" + isd->nick + "!" + isd->username + "@" + tcp_session->get_their_addr().to_str() + " PART " + channel + "\r\n";

			transmit_to_channel(channel, part_line, isd->nick);

			send_user_for_channel(channel, "___\x03invalid");
		}

		return true;
	}

	if ((parts.at(0) == "PRIVMSG" || parts.at(0) == "NOTICE") && parts.size() >= 2) {
		auto target = str_tolower(parts.at(1));

		std::unique_lock<std::mutex> lck(nicknames_lock);

		std::string msg_line = ":" + isd->nick + "!" + isd->username + "@" + tcp_session->get_their_addr().to_str() + " " + line + "\r\n";

		transmit_to_channel(target, msg_line, isd->nick);

		return true;
	}

	if (parts.at(0) == "PING") {
		// :keetweej.vanheusden.com PONG keetweej.vanheusden.com :bla
		std::string reply = ":" + local_host + " PONG " + local_host + " :";

		std::size_t space = line.find(" ");

		if (space != std::string::npos)
			reply += line.substr(space + 1);

		reply += "\r\n";

		if (transmit_to_client(tcp_session, reply) == false)
			return false;

		return true;
	}

	if (parts.at(0) == "TOPIC" && parts.size() >= 3) {
		std::string channel = parts.at(1);

		std::size_t colon   = line.find(":");

		std::string topic   = colon == std::string::npos ? "" : line.substr(colon + 1);

		{
			std::unique_lock<std::mutex> lck(topicnames_lock);

			topicnames.insert_or_assign(channel, topic);
		}

		if (send_topic(tcp_session, channel) == false)
			return false;

		return true;
	}

	if (parts.at(0) == "LIST") {
		std::map<std::string, int> channels;

		{
			std::unique_lock<std::mutex> lck(nicknames_lock);

			channels = get_channel_list();
		}

		std::string start_line = ":" + local_host + " 321 " + isd->nick + " Channel :Users Name\r\n";

		if (transmit_to_client(tcp_session, start_line) == false)
			return false;

		for(auto & ch : channels) {
			std::string topic_line = ":" + local_host + " 322 " + isd->nick + " " + ch.first + " " + myformat("%d", ch.second) + " :[+nt] " + get_topic(ch.first) + "\r\n";

			if (transmit_to_client(tcp_session, topic_line) == false)
				return false;
		}

		std::string end_line = ":" + local_host + " 323 " + isd->nick + " :End of channel list.\r\n";

		if (transmit_to_client(tcp_session, end_line) == false)
			return false;
		
		return true;
	}

	if (parts.at(0) == "QUIT")
		return false;

	return true;
}

void irc_thread(session *const tcp_session)
{
        set_thread_name("myip-irc");

        irc_session_data *isd = dynamic_cast<irc_session_data *>(tcp_session->get_callback_private_data());

	bool seen_nick = false;
	bool seen_user = false;

        for(;isd->terminate == false;) {
		std::unique_lock<std::mutex> lck(isd->r_lock);

		std::size_t crlf = isd->input.find("\r\n");

		if (crlf != std::string::npos) {
			std::string line = isd->input.substr(0, crlf);

			isd->input.erase(0, crlf + 2);

			lck.unlock();

			if (process_line(tcp_session, &seen_nick, &seen_user, line) == false) {
				DOLOG(ll_debug, "irc_thread:: process_line returned abort status\n");

				break;
			}
		}
		else {
			isd->r_cond.wait_for(lck, 500ms);
		}
	}

	{
		std::unique_lock<std::mutex> lck(nicknames_lock);

		nicknames.erase(isd->nick);
	}

	tcp_session->get_stream_target()->end_session(tcp_session);
}

bool irc_new_session(pstream *const t, session *t_s)
{
	irc_session_data *ts = new irc_session_data();

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

	t_s->input += std::string(reinterpret_cast<const char *>(b.get_bytes(data_len)), data_len);

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

		delete nsd;

		ts->set_callback_private_data(nullptr);
	}

	return true;
}

port_handler_t irc_get_handler(stats *const s, const std::string & local_host_in)
{
	port_handler_t tcp_irc;

	tcp_irc.init             = irc_init;
	tcp_irc.new_session      = irc_new_session;
	tcp_irc.new_data         = irc_new_data;
	tcp_irc.session_closed_1 = irc_close_session_1;
	tcp_irc.session_closed_2 = irc_close_session_2;
	tcp_irc.deinit           = irc_deinit;

	tcp_irc.pd               = nullptr;

	local_host               = local_host_in;

	return tcp_irc;
}
