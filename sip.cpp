// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <optional>
#include <sndfile.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "sip.h"
#include "udp.h"
#include "utils.h"


// from
// http://dystopiancode.blogspot.com/2012/02/pcm-law-and-u-law-companding-algorithms.html
int8_t encode_alaw(int16_t number)
{
	const uint16_t ALAW_MAX = 0xFFF;
	uint16_t mask = 0x800;
	uint8_t sign = 0;
	uint8_t position = 11;
	uint8_t lsb = 0;
	if (number < 0)
	{
		number = -number;
		sign = 0x80;
	}
	if (number > ALAW_MAX)
	{
		number = ALAW_MAX;
	}
	for (; ((number & mask) != mask && position >= 5); mask >>= 1, position--);
	lsb = (number >> ((position == 4) ? (1) : (position - 4))) & 0x0f;
	return (sign | ((position - 4) << 4) | lsb) ^ 0x55;
}

sip::sip(stats *const s, udp *const u, const std::string & sample) : u(u)
{
	th = new std::thread(std::ref(*this));

	SF_INFO sfinfo { 0 };
	SNDFILE *fh = sf_open(sample.c_str(), SFM_READ, &sfinfo);
	if (!fh) {
		dolog(error, "SIP \"%s\" cannot be opened\n", sample.c_str());
		exit(1);
	}

	samplerate = sfinfo.samplerate;

	if (sfinfo.channels != 1) {
		dolog(error, "SIP \"%u\": should be mono sample (%s)\n", sfinfo.channels, sample.c_str());
		sf_close(fh);
		exit(1);
	}

	n_samples = sf_seek(fh, 0, SEEK_END);
	sf_seek(fh, 0, SEEK_SET);

	samples = new uint8_t[n_samples];

	short *temp = new short[n_samples];
	if (sf_read_short(fh, temp, n_samples) != n_samples) {
		dolog(error, "SIP short read on \"%s\"\n", sample.c_str());
		sf_close(fh);
		exit(1);
	}

	for(int i=0; i<n_samples; i++)
		samples[i] = encode_alaw(temp[i]);

	delete [] temp;

	sf_close(fh);
}

sip::~sip()
{
	stop_flag = true;

	th->join();
	delete th;

	delete [] samples;
}

void sip::input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p)
{
	dolog(info, "SIP packet from [%s]:%u\n", src_ip.to_str().c_str(), src_port);

	auto pl = p->get_payload();

	std::string pl_str = std::string((const char *)pl.first, pl.second);

	std::vector<std::string> *header_body = split(pl_str, "\r\n\r\n");

	std::vector<std::string> *header_lines = split(header_body->at(0), "\r\n");

	std::vector<std::string> *parts = split(header_lines->at(0), " ");

	dolog(debug, "%s", std::string((const char *)pl.first, pl.second).c_str());

	if (parts->size() == 3 && parts->at(0) == "OPTIONS" && parts->at(2) == "SIP/2.0") {
		reply_to_OPTIONS(src_ip, src_port, dst_ip, dst_port, header_lines);
	}
	else if (parts->size() == 3 && parts->at(0) == "INVITE" && parts->at(2) == "SIP/2.0" && header_body->size() == 2) {
		std::vector<std::string> *body_lines = split(header_body->at(1), "\r\n");

		reply_to_INVITE(src_ip, src_port, dst_ip, dst_port, header_lines, body_lines);

		delete body_lines;
	}
	else {
		dolog(info, "SIP request \"%s\" not understood\n", header_lines->at(0).c_str());
	}

	delete parts;

	delete header_lines;

	delete header_body;
}

void create_response_headers(std::vector<std::string> *const target, const std::vector<std::string> *const source, const size_t c_size, const any_addr & my_ip)
{
	target->push_back("SIP/2.0 200 OK");

	auto str_via = find_header(source, "Via");
	auto str_from = find_header(source, "From");
	auto str_to = find_header(source, "To");
	auto str_call_id = find_header(source, "Call-ID");
	auto str_cseq = find_header(source, "CSeq");

	if (str_via.has_value())
		target->push_back("Via: " + str_via.value());

	if (str_from.has_value())
		target->push_back("From: " + str_from.value());
	if (str_to.has_value())
		target->push_back("To: " + str_to.value());

	if (str_call_id.has_value())
		target->push_back("Call-ID: " + str_call_id.value());

	if (str_cseq.has_value())
		target->push_back("CSeq: " + str_cseq.value());

	target->push_back(myformat("Server: %s", my_ip.to_str().c_str()));

	//target->push_back("Allow: INVITE, ASK, CANCEL, OPTIONS, BYE");
	target->push_back("Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE");

	if (str_to.has_value()) {
		std::string::size_type lt = str_to.value().rfind('<');
		std::string::size_type gt = str_to.value().rfind('>');

		std::string contact = str_to.value().substr(lt, gt - lt + 1);

		target->push_back(myformat("Contact: %s", contact.c_str()));
	}

	target->push_back("User-Agent: MyIP - https://github.com/folkertvanheusden/myip");

	target->push_back("Content-Type: application/sdp");
	target->push_back(myformat("Content-Length: %zu", c_size));
}

void sip::reply_to_OPTIONS(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers)
{
	std::vector<std::string> content;
	content.push_back("v=0");
	content.push_back("o=jdoe 0 0 IN IP4 " + dst_ip.to_str()); // my ip
	content.push_back("c=IN IP4 " + dst_ip.to_str()); // my ip
	content.push_back("s=MyIP");
	content.push_back("t=0 0");
	// 1234 could be allocated but as this is send-
	// only, it is not relevant
	content.push_back("m=audio 1234 RTP/AVP 8");
	content.push_back("a=sendonly");
	content.push_back(myformat("a=rtpmap:8 PCMA/%u", samplerate));

	std::string content_out = merge(content, "\r\n");

	std::vector<std::string> hout;
	create_response_headers(&hout, headers, content_out.size(), dst_ip);
	std::string headers_out = merge(hout, "\r\n");

	std::string out = headers_out + "\r\n" + content_out;

	u->transmit_packet(src_ip, src_port, dst_ip, dst_port, (const uint8_t *)out.c_str(), out.size());
}

void sip::reply_to_INVITE(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers, const std::vector<std::string> *const body)
{
	std::vector<std::string> content;
	content.push_back("v=0");
	content.push_back("o=jdoe 0 0 IN IP4 " + dst_ip.to_str()); // my ip
	content.push_back("c=IN IP4 " + dst_ip.to_str()); // my ip
	content.push_back("s=MyIP");
	content.push_back("t=0 0");
	// 1234 could be allocated but as this is send-only,
	// it is not relevant
	content.push_back("m=audio 1234 RTP/AVP 8");
	content.push_back("a=sendonly");
	content.push_back(myformat("a=rtpmap:8 PCMA/%u", samplerate));

	std::string content_out = merge(content, "\r\n");

	std::vector<std::string> hout;
	create_response_headers(&hout, headers, content_out.size(), dst_ip);
	std::string headers_out = merge(hout, "\r\n");

	std::string out = headers_out + "\r\n" + content_out;

	dolog(debug, "%s", out.c_str());

	u->transmit_packet(src_ip, src_port, dst_ip, dst_port, (const uint8_t *)out.c_str(), out.size());

	auto m = find_header(body, "m", "=");

	if (m.has_value()) {
		std::vector<std::string> *m_parts = split(m.value(), " ");
	
		int tgt_rtp_port = m_parts->size() >= 2 ? atoi(m_parts->at(1).c_str()) : 8000;

		sip_session_t *ss = new sip_session_t();
		ss->start_ts = get_us();

		// 1234: see m=... above
		std::thread *th = new std::thread(&sip::transmit_wav, this, src_ip, tgt_rtp_port, dst_ip, 1234, ss);

		slock.lock();
		sessions.insert({ th, ss });
		slock.unlock();

		delete m_parts;
	}
}

void sip::transmit_wav(const any_addr & tgt_addr, const int tgt_port, const any_addr & src_addr, const int src_port, sip_session_t *const ss)
{
	set_thread_name("myip-siprtp");

	uint16_t seq_nr = 0;
	uint32_t t = 0;

	uint32_t ssrc;
	get_random((uint8_t *)&ssrc, sizeof ssrc);

	int n_work = n_samples, offset = 0;

	while(n_work > 0) {
		int cur_n = std::min(n_work, 500);

		bool odd = cur_n & 1;

		size_t size = 3 * 4 + (cur_n + odd) * sizeof(uint8_t);
		uint8_t *rtp_packet = new uint8_t[size]();

		rtp_packet[0] |= 128;  // v2
		rtp_packet[1] = 8;  // a-law
		rtp_packet[2] = seq_nr >> 8;
		rtp_packet[3] = seq_nr;
		rtp_packet[4] = t >> 24;
		rtp_packet[5] = t >> 16;
		rtp_packet[6] = t >>  8;
		rtp_packet[7] = t;
		rtp_packet[8] = ssrc >> 24;
		rtp_packet[9] = ssrc >> 16;
		rtp_packet[10] = ssrc >>  8;
		rtp_packet[11] = ssrc;

		memcpy(&rtp_packet[12], &samples[offset], cur_n);
		offset += cur_n;
		n_work -= cur_n;
		t += cur_n;

		u->transmit_packet(tgt_addr, tgt_port, src_addr, src_port, rtp_packet, size);

		delete [] rtp_packet;

		seq_nr++;

		double sleep = 1000000.0 / (samplerate / double(cur_n));
		myusleep(sleep);
	}

	ss->finished = true;
}

void sip::operator()()
{
	set_thread_name("myip-sip");

	while(!stop_flag) {
		myusleep(500000);

		slock.lock();
		for(auto it=sessions.begin(); it!=sessions.end();) {
			if (it->second->finished) {
				it->first->join();

				delete it->second;
				delete it->first;

				it = sessions.erase(it);
			}
			else {
				it++;
			}
		}
		slock.unlock();
	}
}
