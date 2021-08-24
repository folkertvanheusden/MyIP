// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <optional>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "sip.h"
#include "udp.h"
#include "utils.h"


sip::sip(stats *const s, udp *const u) : u(u)
{
	th = new std::thread(std::ref(*this));
}

sip::~sip()
{
	stop_flag = true;
	th->join();
	delete th;
}

void sip::input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p)
{
	dolog(info, "SIP packet from [%s]:%u\n", src_ip.to_str().c_str(), src_port);

	auto pl = p->get_payload();

	std::string pl_str = std::string((const char *)pl.first, pl.second);
	std::vector<std::string> *lines = split(pl_str, "\r\n");

	std::vector<std::string> *parts = split(lines->at(0), " ");

	dolog(debug, "%s", std::string((const char *)pl.first, pl.second).c_str());

	if (parts->size() == 3 && parts->at(0) == "OPTIONS" && parts->at(2) == "SIP/2.0") {
		reply_to_OPTIONS(src_ip, src_port, dst_ip, dst_port, lines);
	}
	else if (parts->size() == 3 && parts->at(0) == "INVITE" && parts->at(2) == "SIP/2.0") {
		reply_to_INVITE(src_ip, src_port, dst_ip, dst_port, lines);
	}
	else {
		dolog(info, "SIP request \"%s\" not understood\n", lines->at(0).c_str());
	}

	delete parts;

	delete lines;
}

void create_response_headers(std::vector<std::string> *const target, const std::vector<std::string> *const source, const size_t c_size, const any_addr & my_ip)
{
	target->push_back("SIP/2 200 OK");

	auto str_via = find_header(source, "Via");
	auto str_from = find_header(source, "From");
	auto str_to = find_header(source, "To");
	auto str_call_id = find_header(source, "Call-ID");
	auto str_cseq = find_header(source, "CSeq");

	if (str_via.has_value())
		target->push_back("Via: " + str_via.value());

	// swap from/to
	if (str_to.has_value()) {
		target->push_back("From: " + str_to.value());

		std::string::size_type lt = str_to.value().rfind('<');
		std::string::size_type gt = str_to.value().rfind('>');

		std::string contact = str_to.value().substr(lt, gt - lt + 1);

		target->push_back(myformat("Contact: %s", contact.c_str()));
	}
	if (str_from.has_value())
		target->push_back("To: " + str_from.value());

	if (str_call_id.has_value())
		target->push_back("Call-ID: " + str_call_id.value());

	if (str_cseq.has_value())
		target->push_back("CSeq: " + str_cseq.value());

	target->push_back(myformat("Server: %s", my_ip.to_str().c_str()));

	target->push_back("Allow: INVITE, ASK, CANCEL, OPTIONS, BYE");

	if (str_to.has_value()) {
		std::string::size_type lt = str_to.value().rfind('<');
		std::string::size_type gt = str_to.value().rfind('>');

		std::string contact = str_to.value().substr(lt, gt - lt + 1);

		target->push_back(myformat("Contact: %s", contact.c_str()));
	}

	target->push_back("Content-Type: application/sdp");
	target->push_back(myformat("Content-Length: %zu", c_size));
}

void sip::reply_to_OPTIONS(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers)
{
	std::vector<std::string> content;
	content.push_back("v=0");
	content.push_back("o=jdoe 0 0 IN IP4 " + src_ip.to_str());
	content.push_back("s=MyIP");
	content.push_back("t=0 0");
	// 1234 could be allocated but as this is send-only,
	// it is not relevant
	content.push_back("m=audio 1234 RTP/AVP 0");
	content.push_back("a=sendonly");
	content.push_back("a=rtpmap:0 PCMU/8000");

	std::string content_out = merge(content, "\r\n");

	std::vector<std::string> hout;
	create_response_headers(&hout, headers, content_out.size(), dst_ip);
	std::string headers_out = merge(hout, "\r\n");

	std::string out = headers_out + "\r\n" + content_out;

	u->transmit_packet(src_ip, src_port, dst_ip, dst_port, (const uint8_t *)out.c_str(), out.size());
}

void sip::reply_to_INVITE(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers)
{
	std::vector<std::string> content;
	content.push_back("v=0");
	content.push_back("o=jdoe 0 0 IN IP4 " + src_ip.to_str());
	content.push_back("s=MyIP");
	content.push_back("t=0 0");
	// 1234 could be allocated but as this is send-only,
	// it is not relevant
	content.push_back("m=audio 1234 RTP/AVP 0");
	content.push_back("a=sendonly");
	content.push_back("a=rtpmap:0 PCMU/8000");

	std::string content_out = merge(content, "\r\n");

	std::vector<std::string> hout;
	create_response_headers(&hout, headers, content_out.size(), dst_ip);
	std::string headers_out = merge(hout, "\r\n");

	std::string out = headers_out + "\r\n" + content_out;

	dolog(debug, "%s", out.c_str());

	u->transmit_packet(src_ip, src_port, dst_ip, dst_port, (const uint8_t *)out.c_str(), out.size());
}

void sip::operator()()
{
	set_thread_name("myip-sip");

	while(!stop_flag) {
		myusleep(500000);

		// FIXME something
	}
}
