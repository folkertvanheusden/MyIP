// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <vector>
#include <bearssl/bearssl.h>

#include "BearSSLHelpers.h"
#include "log.h"
#include "str.h"
#include "tcp.h"
#include "utils.h"
#include "ipv4.h"
#include "types.h"
#include "stats_utils.h"


using namespace std::chrono_literals;

std::vector<uint8_t> str_to_vector(const std::string & in)
{
	return std::vector<uint8_t>(reinterpret_cast<const uint8_t *>(in.c_str()), reinterpret_cast<const uint8_t *>(in.c_str() + in.size()));
}

std::optional<std::pair<std::string, std::vector<uint8_t> > > generate_response(session *const ts, const std::string & request)
{
	http_session_data *hs  = dynamic_cast<http_session_data *>(ts->get_callback_private_data());
	http_private_data *hpd = dynamic_cast<http_private_data *>(ts->get_application_private_data());

	std::string logfile  = hpd->logfile;
	std::string web_root = hpd->web_root;

	std::size_t end_marker = request.find("\r\n\r\n");

	if (end_marker == std::string::npos) {
		DOLOG(ll_info, "HTTP: empty request?\n");

		stats_inc_counter(hpd->http_r_err);

		return { };
	}

	std::vector<std::string> lines = split(request.substr(0, end_marker), "\r\n");

	if (lines.size() == 0) {
		DOLOG(ll_info, "HTTP: empty request?\n");

		stats_inc_counter(hpd->http_r_err);

		return { };
	}

	auto parts = split(lines.at(0), " ");

	if (parts.size() < 3) {
		DOLOG(ll_warning, "HTTP: invalid request: %s\n", lines.at(0).c_str());

		stats_inc_counter(hpd->http_r_err);

		return { };
	}

	std::string url  = parts.at(1);

	int         rc   = 200;

	auto        host = find_header(&lines, "Host");

	if (url == "" || url == "/")
		url = "index.html";

	std::string            path      = web_root + "/" + (host.has_value() ? host.value() : "default") + "/" + url;

	std::string::size_type dot       = url.rfind(".");
	std::string            ext       = dot == std::string::npos ? "" : url.substr(dot);
	std::string            mime_type = "text/plain";

	if (ext == ".html")
		mime_type = "text/html";
	else if (ext == ".ico")
		mime_type = "image/x-icon";

	std::vector<uint8_t> content;

	size_t file_size = 0;
	if (url.find("..") != std::string::npos) {
		rc      = 500;
		content = str_to_vector("Server error.");
	}
	else if (url == "/stats.json") {
		content   = str_to_vector(hpd->s->to_json());
		mime_type = "application/json";
	}
	else if (file_exists(path, &file_size) == false) {
		rc      = 404;
		content = str_to_vector("File does not exist.");
		DOLOG(ll_debug, "HTTP: requested file \"%s\" does not exist", path.c_str());
	}
	else {
		content.resize(file_size);

		FILE *fh = fopen(path.c_str(), "rb");
		if (fh) {
			int frc = fread(content.data(), 1, file_size, fh);
			fclose(fh);

			if (size_t(frc) != file_size) {
				rc      = 500;
				content = str_to_vector("Cannot read file.");
			}
		}
		else {
			rc      = 500;
			content = str_to_vector("File disappeared before it could be read.");
		}
	}

	std::string header;

	if (rc == 200) {
		header = myformat("HTTP/1.0 %d OK\r\nServer: MyIP\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", rc, mime_type.c_str(), content.size());
		stats_inc_counter(hpd->http_r_200);
	}
	else {
		header = myformat("HTTP/1.0 %d Something is wrong\r\nServer: MyIP\r\nConnection: close\r\n\r\n", rc);

		if (rc == 404)
			stats_inc_counter(hpd->http_r_404);
		else if (rc == 500)
			stats_inc_counter(hpd->http_r_500);
	}

	DOLOG(ll_debug, "HTTP: Send response %d for %s: %s\n", rc, hs->client_addr.c_str(), url.c_str());

	FILE *fh = fopen(logfile.c_str(), "a+");
	if (fh) {
		auto      temp = ts->get_session_creation_time();

		tm tm { 0 };
		gmtime_r(&temp.tv_sec, &tm);

		constexpr const char *const month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

		auto referer    = find_header(&lines, "Referer");
		auto user_agent = find_header(&lines, "User-Agent");

		fprintf(fh, "%s - - [%02d/%s/%04d:%02d:%02d:%02d +0000] \"%s\" %d %ld \"%s\" \"%s\"\n",
				hs->client_addr.c_str(),
				tm.tm_mday, month[tm.tm_mon], tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,
				(parts.at(0) + " " + parts.at(1) + " " + parts.at(2)).c_str(),
				rc,
				content.size(),
				(referer.has_value()    ? referer.value()    : "-").c_str(),
				(user_agent.has_value() ? user_agent.value() : "-").c_str());

		fclose(fh);
	}
	else {
		DOLOG(ll_error, "HTTP: Cannot access log file (%s): %s\n", logfile.c_str(), strerror(errno));
	}

	return { { header, content } };
}

void http_thread(session *ts)
{
        set_thread_name("myip-http");

        http_session_data *hs = dynamic_cast<http_session_data *>(ts->get_callback_private_data());

        for(;hs->terminate == false;) {
		std::unique_lock<std::mutex> lck(hs->r_lock);

		if (hs->req_data) {
			char *end_marker = strstr(hs->req_data, "\r\n\r\n");
			if (end_marker) {
				auto rc = generate_response(ts, hs->req_data);

				lck.unlock();

				if (rc.has_value()) {
					if (ts->get_stream_target()->send_data(ts, (const uint8_t *)rc.value().first.c_str(), rc.value().first.size())) {
						if (rc.value().second.empty() == false)
							ts->get_stream_target()->send_data(ts, rc.value().second.data(), rc.value().second.size());
					}
				}

				ts->get_stream_target()->end_session(ts);

				break;
			}
		}

		hs->r_cond.wait_for(lck, 500ms);
	}
}

typedef struct {
	http_session_data *hs;
	session           *s;
} https_ctx;

int sock_read(void *ctx, unsigned char *buf, size_t len)
{
	https_ctx *const hc = reinterpret_cast<https_ctx *>(ctx);

	for(;!hc->s->get_is_terminating() && !hc->hs->terminate;) {
		std::unique_lock<std::mutex> lck(hc->hs->r_lock);

		if (hc->hs->req_len >= len) {
			memcpy(buf, hc->hs->req_data, len);

			size_t left = hc->hs->req_len - len;

			if (left > 0)
				memmove(&hc->hs->req_data[0], &hc->hs->req_data[len], left);

			hc->hs->req_len -= len;

			return len;
		}

		hc->hs->r_cond.wait_for(lck, 100ms);
	}

	return -1;
}

int sock_write(void *ctx, const unsigned char *buf, size_t len)
{
	https_ctx *const hc = reinterpret_cast<https_ctx *>(ctx);

	if (hc->s->get_stream_target()->send_data(hc->s, buf, len))
		return len;

	return -1;
}

void https_thread(session *ts)
{
        set_thread_name("myip-https");

        http_session_data *hs  = dynamic_cast<http_session_data *>(ts->get_callback_private_data());
	http_private_data *hpd = dynamic_cast<http_private_data *>(ts->get_application_private_data());

	https_ctx             hc  { hs, ts };

	br_ssl_server_context sc  { 0 };
	unsigned char         iobuf[BR_SSL_BUFSIZE_BIDI] { 0 };
	br_sslio_context      ioc { 0 };

	BearSSL::X509List c(hpd->certificate.c_str());
	const br_x509_certificate *br_c       = c.getX509Certs();
	size_t                     br_c_count = c.getCount();

	BearSSL::PrivateKey pk(hpd->private_key.c_str());

	if (pk.isRSA()) {
		DOLOG(ll_debug, "https: private key is an RSA key\n");
		const br_rsa_private_key *br_pk = pk.getRSA();

		br_ssl_server_init_full_rsa(&sc, br_c, br_c_count, br_pk);
	}
	else if (pk.isEC()) {
		DOLOG(ll_debug, "https: private key is an EC key\n");
		const br_ec_private_key *br_pk = pk.getEC();

		br_ssl_server_init_full_ec(&sc, br_c, br_c_count, BR_KEYTYPE_EC, br_pk);
	}
	else {
		error_exit(false, "https_thread: private key is not RSA or EC");
	}

	br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);

	br_ssl_server_reset(&sc);

	br_sslio_init(&ioc, &sc.eng, sock_read, &hc, sock_write, &hc);

	std::string headers;

	bool        ok      = true;

        for(;hs->terminate == false;) {
		char x { 0 };

		if (br_sslio_read(&ioc, &x, 1) < 0) {
			ok = false;
			break;
		}

		headers += x;

		if (x == 0x0a) {
			if (headers.find("\r\n\r\n") != std::string::npos) {
				auto rc = generate_response(ts, headers);

				if (rc.has_value()) {
					if (br_sslio_write_all(&ioc, (const uint8_t *)rc.value().first.c_str(), rc.value().first.size()) == -1)
						ok = false;
					else if (rc.value().second.empty() == false)
						ok = br_sslio_write_all(&ioc, rc.value().second.data(), rc.value().second.size()) == 0;
				}
				else {
					ok = false;
				}

				break;
			}
		}
	}

	if (ok && hs->terminate == false) {
		ts->set_is_terminating();

// this often ends in a busy loop in bearssl
//		br_sslio_close(&ioc);
	}

	ts->get_stream_target()->end_session(ts);
}

bool http_new_session(pstream *const t, session *ts)
{
	http_session_data *hs = new http_session_data();
	hs->req_data = nullptr;
	hs->req_len  = 0;

	any_addr src_addr = ts->get_their_addr();
	hs->client_addr   = src_addr.to_str();

	ts->set_callback_private_data(hs);

	stats_inc_counter(dynamic_cast<http_private_data *>(ts->get_application_private_data())->http_requests);

	http_private_data *hpd = dynamic_cast<http_private_data *>(ts->get_application_private_data());

	hs->th = new std::thread(hpd->is_https ? https_thread : http_thread, ts);

	return true;
}

bool http_new_data(pstream *ps, session *ts, buffer_in b)
{
	http_session_data *hs = dynamic_cast<http_session_data *>(ts->get_callback_private_data());

	if (!hs) {
		DOLOG(ll_info, "HTTP: Data for a non-existing session\n");
		stats_inc_counter(dynamic_cast<http_private_data *>(ts->get_application_private_data())->http_r_err);
		return false;
	}

	int data_len = b.get_n_bytes_left();

	if (data_len == 0) {
		DOLOG(ll_debug, "HTTP: client closed session\n");
		return true;
	}

	const std::lock_guard<std::mutex> lck(hs->r_lock);

	hs->req_data = (char *)realloc(hs->req_data, hs->req_len + data_len + 1);

	memcpy(&hs->req_data[hs->req_len], b.get_bytes(data_len), data_len);
	hs->req_len += data_len;
	hs->req_data[hs->req_len] = 0x00;

	hs->r_cond.notify_one();

	return true;
}

bool http_close_session_1(pstream *const ps, session *const ts)
{
	return true;
}

bool http_close_session_2(pstream *const ps, session *ts)
{
	http_session_data *hs  = dynamic_cast<http_session_data *>(ts->get_callback_private_data());

	if (hs) {
		hs->terminate = true;

		hs->th->join();
		delete hs->th;
		hs->th = nullptr;

		free(hs->req_data);

		delete hs;

		ts->set_callback_private_data(nullptr);
	}

	return true;
}

port_handler_t http_get_handler(stats *const s, const std::string & web_root, const std::string & logfile, const bool is_https)
{
	port_handler_t http { 0 };

	http.init              = nullptr;
	http.new_session       = http_new_session;
	http.new_data          = http_new_data;
	http.session_closed_1  = http_close_session_1;
	http.session_closed_2  = http_close_session_2;
	http.deinit            = nullptr;

	http_private_data *hpd = new http_private_data();
	hpd->logfile           = logfile;
	hpd->web_root          = web_root;
	hpd->s                 = s;
	hpd->is_https          = is_https;

	// 1.3.6.1.4.1.57850: vanheusden.com
	// 1.3.6.1.4.1.57850.1: myip
	// 1.3.6.1.4.1.57850.1.1: http
	hpd->http_requests     = s->register_stat("http_requests", "1.3.6.1.4.1.57850.1.1.1");
	hpd->http_r_200        = s->register_stat("http_r_200", "1.3.6.1.4.1.57850.1.1.2");
	hpd->http_r_404        = s->register_stat("http_r_404", "1.3.6.1.4.1.57850.1.1.3");
	hpd->http_r_500        = s->register_stat("http_r_500", "1.3.6.1.4.1.57850.1.1.4");
	hpd->http_r_err        = s->register_stat("http_r_err", "1.3.6.1.4.1.57850.1.1.5");

	http.pd                = hpd;

	return http;
}
