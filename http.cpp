// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tcp.h"
#include "utils.h"
#include "ipv4.h"
#include "types.h"
#include "stats-utils.h"

bool http_new_session(tcp_session_t *ts, const packet *pkt, private_data *pd)
{
	http_session_data *hs = new http_session_data();
	hs->req_data = nullptr;
	hs->req_len = 0;

	any_addr src_addr = pkt->get_src_addr();
	hs->client_addr = src_addr.to_str();

	ts->p = hs;

	stats_inc_counter(dynamic_cast<http_private_data *>(pd)->http_requests);

	return true;
}

void send_response(tcp_session_t *ts, const packet *pkt, char *request, private_data *pd)
{
	http_session_data *hs = dynamic_cast<http_session_data *>(ts->p);
	http_private_data *hpd = dynamic_cast<http_private_data *>(pd);
	std::string logfile = hpd->logfile;
	std::string web_root = hpd->web_root;

	char *endm = strstr(request, "\r\n\r\n");
	if (endm)
		*endm = 0x00;

	std::vector<std::string> *lines = split(request, "\r\n");

	if (lines->size() == 0) {
		dolog(info, "HTTP: empty request?\n");
		delete lines;
		stats_inc_counter(dynamic_cast<http_private_data *>(pd)->http_r_err);
		return;
	}

	auto parts = split(lines->at(0), " ");

	if (parts->size() < 3) {
		dolog(warning, "HTTP: invalid request: %s\n", lines->at(0).c_str());
		delete parts;
		delete lines;
		stats_inc_counter(dynamic_cast<http_private_data *>(pd)->http_r_err);
		return;
	}

	std::string url = parts->at(1);
	bool get = parts->at(0) == "GET";

	int rc = 200;
	uint8_t *reply = nullptr;
	long content_len = 0;

	auto host = find_header(lines, "Host");

	if (url == "" || url == "/")
		url = "index.html";

	std::string path = web_root + "/" + (host.has_value() ? host.value() : "default") + "/" + url;

	std::string::size_type dot = url.rfind(".");
	std::string ext = dot == std::string::npos ? "" : url.substr(dot);
	std::string mime_type = "text/plain";

	if (ext == ".html")
		mime_type = "text/html";
	else if (ext == ".ico")
		mime_type = "image/x-icon";

	size_t file_size = 0;
	if (url.find("..") != std::string::npos) {
		rc = 500;
		reply = (uint8_t *)strdup("Server error.");
		content_len = strlen((const char *)reply);
	}
	else if (url == "/stats.json") {
		reply = (uint8_t *)strdup(hpd->s->to_json().c_str());
		content_len = strlen((const char *)reply);
		mime_type = "application/json";
	}
	else if (file_exists(path, &file_size) == false) {
		rc = 404;
		reply = (uint8_t *)strdup("File does not exist.");
		content_len = strlen((const char *)reply);
		dolog(debug, "HTTP: requested file \"%s\" does not exist", path.c_str());
	}
	else {
		reply = (uint8_t *)calloc(1, file_size);
		content_len = file_size;

		FILE *fh = fopen(path.c_str(), "rb");
		if (fh) {
			int frc = fread(reply, 1, file_size, fh);
			fclose(fh);

			if (size_t(frc) != file_size) {
				rc = 500;
				free(reply);
				reply = (uint8_t *)strdup("Short read.");
				content_len = strlen((const char *)reply);
			}
		}
		else {
			rc = 500;
			free(reply);
			reply = (uint8_t *)strdup("File went away.");
			content_len = strlen((const char *)reply);
		}
	}

	std::string header;

	if (rc == 200) {
		header = myformat("HTTP/1.0 %d OK\r\nServer: MyIP\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", rc, mime_type.c_str(), content_len);
		stats_inc_counter(dynamic_cast<http_private_data *>(pd)->http_r_200);
	}
	else {
		header = myformat("HTTP/1.0 %d Something is wrong\r\nServer: MyIP\r\nConnection: close\r\n\r\n", rc);

		if (rc == 404)
			stats_inc_counter(dynamic_cast<http_private_data *>(pd)->http_r_404);
		else if (rc == 500)
			stats_inc_counter(dynamic_cast<http_private_data *>(pd)->http_r_500);
	}

	dolog(debug, "HTTP: Send response %d for %s: %s\n", rc, hs->client_addr.c_str(), url.c_str());

	FILE *fh = fopen(logfile.c_str(), "a+");
	if (fh) {
		auto tv = pkt->get_recv_ts();
		struct tm tm { 0 };
		gmtime_r(&tv.tv_sec, &tm);

		const char *const month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

		auto referer = find_header(lines, "Referer");
		auto user_agent = find_header(lines, "User-Agent");

		fprintf(fh, "%s - - [%02d/%s/%04d:%02d:%02d:%02d +0000] \"%s\" %d %ld \"%s\" \"%s\"\n",
				hs->client_addr.c_str(),
				tm.tm_mday, month[tm.tm_mon], tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,
				(parts->at(0) + " " + parts->at(1) + " " + parts->at(2)).c_str(),
				rc,
				content_len,
				(referer.has_value() ? referer.value() : "-").c_str(),
				(user_agent.has_value() ? user_agent.value() : "-").c_str());

		fclose(fh);
	}
	else {
		dolog(error, "HTTP: Cannot access log file (%s): %s\n", logfile.c_str(), strerror(errno));
	}

	delete parts;

	ts->t->send_data(ts, (const uint8_t *)header.c_str(), header.size(), true);

	if (get) {
		if (reply) {
			ts->t->send_data(ts, reply, content_len, true);
		}
		else {
			const char err[] = "Something went wrong: you should not see this.";

			ts->t->send_data(ts, (const uint8_t *)err, sizeof(err) - 1, true);
		}
	}

	ts->t->end_session(ts, pkt);

	delete lines;

	free(reply);
}

bool http_new_data(tcp_session_t *ts, const packet *pkt, const uint8_t *data, size_t data_len, private_data *pd)
{
	http_session_data *hs = dynamic_cast<http_session_data *>(ts->p);

	if (!hs) {
		dolog(info, "HTTP: Data for a non-existing session\n");
		stats_inc_counter(dynamic_cast<http_private_data *>(pd)->http_r_err);
		return false;
	}

	hs->req_data = (char *)realloc(hs->req_data, hs->req_len + data_len + 1);

	memcpy(&hs->req_data[hs->req_len], data, data_len);
	hs->req_len += data_len;
	hs->req_data[hs->req_len] = 0x00;

	char *end_marker = strstr(hs->req_data, "\r\n\r\n");
	if (end_marker)
		send_response(ts, pkt, hs->req_data, pd);

	return true;
}

void http_close_session_1(tcp_session_t *ts, private_data *pd)
{
	if (ts -> p) {
		http_session_data *hs = dynamic_cast<http_session_data *>(ts->p);
		free(hs->req_data);

		delete hs;

		ts->p = nullptr;
	}
}

void http_close_session_2(tcp_session_t *ts, private_data *pd)
{
}

tcp_port_handler_t http_get_handler(stats *const s, const std::string & web_root, const std::string & logfile)
{
	tcp_port_handler_t tcp_http;

	tcp_http.init = nullptr;
	tcp_http.new_session = http_new_session;
	tcp_http.new_data = http_new_data;
	tcp_http.session_closed_1 = http_close_session_1;
	tcp_http.session_closed_2 = http_close_session_2;
	tcp_http.deinit = nullptr;

	http_private_data *hpd = new http_private_data();
	hpd->logfile = logfile;
	hpd->web_root = web_root;
	hpd->s = s;

	hpd->http_requests = s->register_stat("http_requests");
	hpd->http_r_200 = s->register_stat("http_r_200");
	hpd->http_r_404 = s->register_stat("http_r_404");
	hpd->http_r_500 = s->register_stat("http_r_500");
	hpd->http_r_err = s->register_stat("http_r_err");

	tcp_http.pd = hpd;

	return tcp_http;
}
