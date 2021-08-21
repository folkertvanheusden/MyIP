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

typedef struct {
	std::string client_addr;
	char *req_data;
	size_t req_len;
} http_session_t;

bool http_new_session(tcp_session_t *ts, const packet *pkt, void *private_data)
{
	http_session_t *hs = new http_session_t;
	hs->req_data = nullptr;
	hs->req_len = 0;

	std::pair<const uint8_t *, int> src_addr = pkt->get_src_addr();
	hs->client_addr = ip_to_str(src_addr);

	ts->p = hs;

	return true;
}

std::optional<std::string> find_header(std::vector<std::string> *lines, const std::string & key)
{
	std::optional<std::string> value;

	for(auto line : *lines) {
		auto parts = split(line, ":");

		if (parts->size() == 2 && parts->at(0) == key) {
			value = parts->at(1);

			while(value.value().empty() == false && value.value().at(0) == ' ')
				value = value.value().substr(1);
		}

		delete parts;
	}

	return value;
}

void send_response(tcp_session_t *ts, const packet *pkt, char *request, void *private_data)
{
	http_session_t *hs = (http_session_t* )ts->p;
	http_private_data *hpd = (http_private_data *)private_data;
	std::string logfile = hpd->logfile;
	std::string web_root = hpd->web_root;

	char *endm = strstr(request, "\r\n\r\n");
	if (endm)
		*endm = 0x00;

	std::vector<std::string> *lines = split(request, "\r\n");

	if (lines->size() == 0) {
		dolog("HTTP: empty request?\n");
		delete lines;
		return;
	}

	auto parts = split(lines->at(0), " ");

	if (parts->size() < 3) {
		dolog("HTTP: invalid request: %s\n", lines->at(0).c_str());
		delete parts;
		delete lines;
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
	else if (file_exists(path, &file_size) == false) {
		rc = 404;
		reply = (uint8_t *)strdup("File does not exist.");
		content_len = strlen((const char *)reply);
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
	}
	else {
		header = myformat("HTTP/1.0 %d Something is wrong\r\nServer: MyIP\r\nConnection: close\r\n\r\n", rc);
	}

	if (parts->size() >= 2) {
		dolog("HTTP: Send response %d for %s: %s\n", rc, hs->client_addr.c_str(), url.c_str());

		FILE *fh = fopen(logfile.c_str(), "a+");
		if (fh) {
			auto tv = pkt->get_recv_ts();
			struct tm tm { 0 };
			gmtime_r(&tv.tv_sec, &tm);

			const char *const month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

			fprintf(fh, "%s - - [%02d/%s/%04d:%02d:%02d:%02d +0000] \"%s\" %d %zu \"-\" \"\"\n",
					hs->client_addr.c_str(),
					tm.tm_mday, month[tm.tm_mon], tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,
					hs->req_data,
					rc,
					content_len);

			fclose(fh);
		}
		else {
			dolog("HTTP: Cannot access log file (%s): %s\n", logfile.c_str(), strerror(errno));
		}
	}
	else {
		dolog("HTTP: Send response %d for request %s\n", rc, hs->req_data);
	}

	delete parts;

	ts->t->send_data(ts, (const uint8_t *)header.c_str(), header.size(), true);

	if (get) {
		if (reply) {
			ts->t->send_data(ts, reply, content_len, true);

			free(reply);
		}
		else {
			const char err[] = "Something went wrong: you should not see this.";

			ts->t->send_data(ts, (const uint8_t *)err, sizeof(err) - 1, true);
		}
	}

	ts->t->end_session(ts, pkt);

	delete lines;
}

bool http_new_data(tcp_session_t *ts, const packet *pkt, const uint8_t *data, size_t data_len, void *private_data)
{
	http_session_t *hs = (http_session_t* )ts->p;

	if (!hs) {
		dolog("HTTP: Data for a non-existing session\n");
		return false;
	}

	hs->req_data = (char *)realloc(hs->req_data, hs->req_len + data_len + 1);

	memcpy(&hs->req_data[hs->req_len], data, data_len);
	hs->req_len += data_len;
	hs->req_data[hs->req_len] = 0x00;

	char *end_marker = strstr(hs->req_data, "\r\n\r\n");
	if (end_marker)
		send_response(ts, pkt, hs->req_data, private_data);

	return true;
}

void http_close_session(tcp_session_t *ts, void *private_data)
{
	if (ts -> p) {
		http_session_t *hs = (http_session_t* )ts->p;
		free(hs->req_data);

		delete hs;

		ts->p = nullptr;
	}
}

tcp_port_handler_t http_get_handler(const std::string & web_root, const std::string & logfile)
{
	tcp_port_handler_t tcp_http;

	tcp_http.init = nullptr;
	tcp_http.new_session = http_new_session;
	tcp_http.new_data = http_new_data;
	tcp_http.session_closed = http_close_session;
	http_private_data *hpd = new http_private_data();
	tcp_http.private_data = hpd;
	hpd->logfile = logfile;
	hpd->web_root = web_root;

	return tcp_http;
}
