// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under AGPL v3.0
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tcp.h"
#include "utils.h"
#include "ipv4.h"

constexpr uint8_t favicon_ico[] = {
  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x40, 0x40, 0x10, 0x00, 0x01, 0x00,
  0x04, 0x00, 0x03, 0x02, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x89, 0x50,
  0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
  0x44, 0x52, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x40, 0x08, 0x06,
  0x00, 0x00, 0x00, 0xaa, 0x69, 0x71, 0xde, 0x00, 0x00, 0x01, 0xca, 0x49,
  0x44, 0x41, 0x54, 0x78, 0x9c, 0xed, 0x9a, 0xc9, 0x12, 0x83, 0x20, 0x0c,
  0x40, 0xd9, 0xfe, 0xff, 0x8f, 0x91, 0x9e, 0xd2, 0x61, 0x52, 0xa9, 0x22,
  0x59, 0x08, 0xf2, 0x4e, 0x4e, 0x5d, 0x48, 0x1e, 0x81, 0xaa, 0xe8, 0x4b,
  0x29, 0xc5, 0xbd, 0x98, 0xa0, 0x1d, 0x80, 0x36, 0x5b, 0x80, 0x76, 0x00,
  0xda, 0x6c, 0x01, 0xda, 0x01, 0x68, 0xb3, 0x05, 0x68, 0x07, 0xa0, 0xcd,
  0x16, 0xa0, 0x1d, 0x80, 0x36, 0x49, 0xa3, 0x51, 0xef, 0xfd, 0xcf, 0x6f,
  0x5a, 0x37, 0xa4, 0x62, 0x02, 0xce, 0x92, 0x6e, 0xed, 0x97, 0x94, 0x21,
  0x32, 0x04, 0xae, 0x92, 0x3f, 0x3b, 0xbe, 0xf7, 0x9c, 0xa7, 0xb0, 0x0b,
  0x18, 0x49, 0x44, 0x42, 0x02, 0xab, 0x00, 0x8a, 0x04, 0xb8, 0x25, 0xb0,
  0x09, 0x90, 0x2a, 0xe1, 0x51, 0x58, 0x04, 0x50, 0x27, 0xcf, 0x29, 0xf3,
  0xf5, 0xf7, 0x01, 0x66, 0x04, 0x70, 0x55, 0x01, 0xb9, 0x00, 0x2b, 0x63,
  0x1f, 0x30, 0x53, 0x01, 0x5c, 0x6c, 0x01, 0xda, 0x01, 0x68, 0xb3, 0x05,
  0x50, 0x5f, 0xd0, 0xda, 0x32, 0x83, 0x99, 0x0a, 0xe0, 0x12, 0xcb, 0x22,
  0xc0, 0x52, 0x15, 0x98, 0xa8, 0x00, 0x4e, 0xa1, 0x6c, 0x02, 0xa8, 0x82,
  0xe6, 0xae, 0x26, 0xd6, 0x0a, 0x18, 0x0d, 0x5e, 0x62, 0x28, 0xb1, 0x0f,
  0x81, 0x52, 0xca, 0xa3, 0x44, 0xa4, 0xe6, 0x11, 0xb1, 0x39, 0xe0, 0x8e,
  0x88, 0x52, 0x8a, 0xcb, 0x39, 0x8b, 0x4e, 0xa2, 0x5e, 0xf3, 0xfb, 0x00,
  0x78, 0x70, 0xaa, 0x43, 0x80, 0xed, 0x65, 0xde, 0x09, 0xb6, 0xa8, 0x13,
  0xc4, 0xdb, 0xcb, 0xbd, 0x15, 0xc6, 0x9c, 0xf5, 0x2e, 0x96, 0x70, 0x1c,
  0x87, 0x48, 0x2c, 0xa2, 0x02, 0xae, 0x5e, 0x77, 0xc3, 0x3e, 0x10, 0xb0,
  0xc4, 0xbf, 0x40, 0x2f, 0x20, 0x21, 0xa5, 0x24, 0x52, 0x05, 0x62, 0x02,
  0x7a, 0x26, 0xb5, 0xfa, 0x58, 0x6e, 0x09, 0x53, 0xae, 0x0c, 0xc1, 0x39,
  0x31, 0x46, 0xdb, 0x02, 0x46, 0x97, 0xb8, 0xbc, 0xf7, 0x2e, 0x84, 0xc0,
  0x2a, 0x61, 0xba, 0x39, 0x00, 0x13, 0x63, 0xb4, 0xf7, 0x30, 0x44, 0xbd,
  0xb8, 0x99, 0x52, 0x72, 0x39, 0x67, 0xb2, 0xeb, 0xd5, 0x4c, 0x5f, 0x01,
  0x40, 0x4a, 0x89, 0xa5, 0x12, 0x48, 0x6f, 0x85, 0x25, 0x6e, 0x5f, 0xa9,
  0x25, 0x98, 0xa9, 0x00, 0x80, 0x5a, 0x32, 0x99, 0x00, 0xc9, 0x15, 0x21,
  0xca, 0xb6, 0x48, 0x04, 0x68, 0x2c, 0x87, 0x51, 0xb5, 0x39, 0x24, 0x40,
  0xf2, 0x53, 0x96, 0x56, 0xfb, 0xa3, 0x98, 0x9b, 0x03, 0x30, 0xa3, 0x12,
  0x1e, 0x09, 0xd0, 0xee, 0x79, 0xcc, 0x48, 0x2c, 0xdd, 0x02, 0x66, 0x4a,
  0xbc, 0xe6, 0x69, 0x5c, 0xe6, 0x87, 0x40, 0xcd, 0x13, 0x09, 0x5d, 0x02,
  0x66, 0xed, 0xfd, 0x9a, 0xde, 0x18, 0x6f, 0x09, 0x98, 0x6d, 0xcc, 0x5f,
  0xd1, 0x13, 0xeb, 0x52, 0x43, 0xa0, 0xe6, 0xae, 0x84, 0xbf, 0x02, 0xac,
  0xf5, 0x3c, 0xe6, 0x4e, 0xec, 0xcb, 0x56, 0x00, 0x70, 0x25, 0xa1, 0x29,
  0xc0, 0x72, 0xcf, 0x63, 0xfe, 0xe5, 0x72, 0x2a, 0x60, 0xa5, 0xe4, 0x81,
  0x56, 0x4e, 0x01, 0x1f, 0xb4, 0x62, 0xf2, 0xc0, 0x59, 0x6e, 0xcb, 0xcf,
  0x01, 0x18, 0x2c, 0x21, 0xb4, 0x76, 0xac, 0x4c, 0x9d, 0x6b, 0xc0, 0x3f,
  0xbc, 0x85, 0xef, 0x32, 0x9c, 0x73, 0xce, 0xce, 0x17, 0x4d, 0x0c, 0x7c,
  0x00, 0xc9, 0xb1, 0x6e, 0x13, 0x5e, 0x10, 0x92, 0x8c, 0x00, 0x00, 0x00,
  0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82
};

constexpr size_t favicon_ico_len = 537;

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

		if (parts->size() == 2 && parts->at(0) == "Host") {
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
	std::string mime_type = "text/html";

	auto host = find_header(lines, "Host");

	const std::string descr = "MyIP - a simple TCP/IP stack written in C++";
	const std::string html_head = "<head><title>" + descr + "</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta charset=\"UTF-8\"></head>";
	const std::string content_404 = "<!doctype html>\n<html>" + html_head + "<body><h1>" + descr + "</h1><p>That URL (" + url + ") is not known.</p></body></html>";

	const std::string hs_gouda_index = "<html><head><meta name=viewport content=\"width=device-width, initial-scale=1\"> <link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/gh/yegor256/tacit@gh-pages/tacit-css.min.css\"/> <title>nu al de meest sympathieke hackerspace van Nederland</title> </head> <body> <section> <article> <h1>hackerspace gouda</h1> <h2>wat is een hackerspace?</h2> <p>Bij \"hackerspace\" denkt men vaak aan inbreken in computers en dan boevenstreken uithalen. Dat is echter niet de betekenis die origineel aan het woord gegeven is. Dat was \"creatief omgaan met spullen\", dat kan zijn met computers maar is niet per definitie zo.</p> <h2>een hackerspace? in Gouda...?</h2> <p>Hackerspace Gouda is nog in oprichting. Kom in ieder geval alvast chatten op IRC (<a href=\"http://webchat.freenode.net?channels=%23hsgouda&uio=d4\">#hsgouda op FreeNode</a>).</p> <h2>contact?</h2> <p>Mailtjes zijn welkom op het volgende adres: <a href=\"mailto:info@hackerspace-gouda.nl\">info@hackerspace-gouda.nl</a></p> <p>Deze website draait NIET op apache of nginx ofzo, deze draait op een zelf-geschreven <a href=\"https://github.com/folkertvanheusden/myip\">IP-stack met daarop een zelf-geschreven web-server</a> en is daarmee de 1e hackerspace (wereldwijd) die dat doet!</p><h2>NTP (tijd) server</h2> <p>Hackerspace Gouda heeft een publieke tijd-server (NTP server) draaien op: <b>ntp.hackerspace-gouda.nl</b></p></article> </section> </body> </html>";

	if (host.has_value() == false || host.value().find("hackerspace-gouda.nl") == std::string::npos) {
		const std::string content = "<!doctype html>\n<html>" + html_head + "<body><h1>" + descr + "</h1><p>This is \"MyIP\", an IP-stack with built-in NTP and HTTP server.</p><p>Written by <a href=\"mailto:mail@vanheusden.com\">Folkert van Heusden (mail@vanheusden.com)</a>.</p><p>Source code can be obtained from <a href=\"https://github.com/folkertvanheusden/MyIP\">GitHub</a>.</p></body></html>";

		if (url != "/" && url != "/favicon.ico")
			rc = 404;

		if (parts->size() >= 1 && get) {
			if (rc == 200) {
				if (url == "/") {
					reply = (uint8_t *)strdup(content.c_str());
					content_len = content.size();
				}
				else {
					reply = (uint8_t *)malloc(favicon_ico_len);
					memcpy(reply, favicon_ico, favicon_ico_len);
					mime_type = "image/x-icon";
				}
			}
			else {
				reply = (uint8_t *)strdup(content_404.c_str());
				content_len = content_404.size();
			}
		}
		else {
			if (rc == 200)
				content_len = url == "/" ? content.size() : favicon_ico_len;
			else
				content_len = content_404.size();
		}
	}
	else if (host.value().find("hackerspace-gouda.nl") != std::string::npos) {
		reply = (uint8_t *)strdup(hs_gouda_index.c_str());
		content_len = hs_gouda_index.size();
	}

	std::string header;

	if (rc == 200) {
		header = myformat("HTTP/1.0 %d OK\r\nServer: MyIP\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", rc, mime_type.c_str(), content_len);
	}
	else {
		header = myformat("HTTP/1.0 %d Not found\r\nServer: MyIP\r\nConnection: close\r\n\r\n", rc);
	}

	if (parts->size() >= 2) {
		dolog("HTTP: Send response %d for %s: %s\n", rc, hs->client_addr.c_str(), url.c_str());
		std::string *logfile = (std::string *)private_data;

		FILE *fh = fopen(logfile->c_str(), "a+");
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
			dolog("HTTP: Cannot access log file (%s): %s\n", logfile->c_str(), strerror(errno));
		}
	}
	else {
		dolog("HTTP: Send response %d for request %s\n", rc, hs->req_data);
	}

	delete parts;

	ts->t->send_data(ts, (const uint8_t *)header.c_str(), header.size(), true);

	if (reply) {
		ts->t->send_data(ts, reply, content_len, true);

		free(reply);
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

tcp_port_handler_t http_get_handler(const std::string & log_file)
{
	tcp_port_handler_t tcp_http;

	tcp_http.init = nullptr;
	tcp_http.new_session = http_new_session;
	tcp_http.new_data = http_new_data;
	tcp_http.session_closed = http_close_session;
	tcp_http.private_data = (void *)new std::string(log_file);

	return tcp_http;
}
