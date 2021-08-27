// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <optional>
#include <sndfile.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <speex/speex.h>
#include <sys/time.h>

#include "sip.h"
#include "udp.h"
#include "utils.h"

typedef struct {
	void *state;
	SpeexBits bits;
} speex_t;

// from
// http://dystopiancode.blogspot.com/2012/02/pcm-law-and-u-law-companding-algorithms.html
int8_t encode_alaw(int16_t number)
{
	uint16_t mask = 0x800;
	uint8_t sign = 0;
	uint8_t position = 11;
	uint8_t lsb = 0;

	if (number < 0) {
		number = -number;
		sign = 0x80;
	}

	number >>= 4; // 16 -> 12

	for(; ((number & mask) != mask && position >= 5); mask >>= 1, position--);

	lsb = (number >> ((position == 4) ? (1) : (position - 4))) & 0x0f;

	return (sign | ((position - 4) << 4) | lsb) ^ 0x55;
}

sip::sip(stats *const s, udp *const u, const std::string & sample, const std::string & mailbox_path) : u(u), mailbox_path(mailbox_path)
{
	sip_requests	= s->register_stat("sip_requests");
	sip_requests_unk= s->register_stat("sip_requests_unk");
	sip_rtp_sessions= s->register_stat("sip_rtp_sessions");
	sip_rtp_codec_8	= s->register_stat("sip_rtp_codec_8");
	sip_rtp_codec_11= s->register_stat("sip_rtp_codec_11");
	sip_rtp_codec_97= s->register_stat("sip_rtp_codec_97");
	sip_rtp_duration= s->register_stat("sip_rtp_duration");

	th = new std::thread(std::ref(*this));

	SF_INFO sfinfo { 0 };
	SNDFILE *fh = sf_open(sample.c_str(), SFM_READ, &sfinfo);
	if (!fh) {
		dolog(error, "SIP: \"%s\" cannot be opened\n", sample.c_str());
		exit(1);
	}

	samplerate = sfinfo.samplerate;

	if (sfinfo.channels != 1) {
		dolog(error, "SIP: \"%u\": should be mono sample (%s)\n", sfinfo.channels, sample.c_str());
		sf_close(fh);
		exit(1);
	}

	n_samples = sf_seek(fh, 0, SEEK_END);
	sf_seek(fh, 0, SEEK_SET);

	samples = new short[n_samples + (n_samples & 1)]();
	if (sf_read_short(fh, samples, n_samples) != n_samples) {
		dolog(error, "SIP: short read on \"%s\"\n", sample.c_str());
		sf_close(fh);
		exit(1);
	}

	sf_close(fh);
}

sip::~sip()
{
	stop_flag = true;

	th->join();
	delete th;

	delete [] samples;
}

void sip::input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, void *const pd)
{
	dolog(info, "SIP: packet from [%s]:%u\n", src_ip.to_str().c_str(), src_port);

	auto pl = p->get_payload();

	std::string pl_str = std::string((const char *)pl.first, pl.second);

	std::vector<std::string> *header_body = split(pl_str, "\r\n\r\n");

	std::vector<std::string> *header_lines = split(header_body->at(0), "\r\n");

	std::vector<std::string> *parts = split(header_lines->at(0), " ");

	stats_inc_counter(sip_requests);

	if (parts->size() == 3 && parts->at(0) == "OPTIONS" && parts->at(2) == "SIP/2.0") {
		reply_to_OPTIONS(src_ip, src_port, dst_ip, dst_port, header_lines);
	}
	else if (parts->size() == 3 && parts->at(0) == "INVITE" && parts->at(2) == "SIP/2.0" && header_body->size() == 2) {
		std::vector<std::string> *body_lines = split(header_body->at(1), "\r\n");

		reply_to_INVITE(src_ip, src_port, dst_ip, dst_port, header_lines, body_lines, pd);

		delete body_lines;
	}
	else if (parts->size() == 3 && parts->at(0) == "BYE" && parts->at(2) == "SIP/2.0") {
		// OK
	}
	else {
		dolog(info, "SIP: request \"%s\" not understood\n", header_lines->at(0).c_str());
		stats_inc_counter(sip_requests_unk);
	}

	delete parts;

	delete header_lines;

	delete header_body;
}

void create_response_headers(const std::string & request, std::vector<std::string> *const target, const bool upd_cseq, const std::vector<std::string> *const source, const size_t c_size, const any_addr & my_ip)
{
	target->push_back(request);

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

	if (str_cseq.has_value()) {
		if (upd_cseq) {
			std::string request_method = request.substr(0, request.find(' '));

			int cseq = str_cseq.has_value() ? atoi(str_cseq.value().c_str()) : 0;

			target->push_back(myformat("CSeq: %u %s", cseq + 1, request_method.c_str()));
		}
		else {
			target->push_back("CSeq: " + str_cseq.value());
		}
	}

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
	std::string proto = dst_ip.get_len() == 4 ? "IP4" : "IP6";
	content.push_back("o=jdoe 0 0 IN " + proto + " " + dst_ip.to_str()); // my ip
	content.push_back("c=IN " + proto + " " + dst_ip.to_str()); // my ip
	content.push_back("s=MyIP");
	content.push_back("t=0 0");
	// 1234 could be allocated but as this is send-
	// only, it is not relevant
	content.push_back("m=audio 1234 RTP/AVP 8 11");
	content.push_back("a=sendrecv");
	content.push_back(myformat("a=rtpmap:8 PCMA/%u", samplerate));
	content.push_back(myformat("a=rtpmap:11 L16/%u", samplerate));
	content.push_back(myformat("a=rtpmap:96 speex/%u", samplerate));
	content.push_back("a=fmtp:97 mode=\"1,any\";vbr=on");

	std::string content_out = merge(content, "\r\n");

	std::vector<std::string> hout;
	create_response_headers("SIP/2.0 200 OK", &hout, false, headers, content_out.size(), dst_ip);
	std::string headers_out = merge(hout, "\r\n");

	std::string out = headers_out + "\r\n" + content_out;

	u->transmit_packet(src_ip, src_port, dst_ip, dst_port, (const uint8_t *)out.c_str(), out.size());
}

void sip::reply_to_INVITE(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers, const std::vector<std::string> *const body, void *const pd)
{
	std::vector<std::string> content;
	content.push_back("v=0");
	std::string proto = dst_ip.get_len() == 4 ? "IP4" : "IP6";
	content.push_back("o=jdoe 0 0 IN " + proto + " " + dst_ip.to_str()); // my ip
	content.push_back("c=IN " + proto + " " + dst_ip.to_str()); // my ip
	content.push_back("s=MyIP");
	content.push_back("t=0 0");

	auto m = find_header(body, "m", "=");

	if (m.has_value()) {
		std::vector<std::string> *m_parts = split(m.value(), " ");

		uint8_t schema = 255;

		for(size_t i=3; i<m_parts->size(); i++) {
			if (m_parts->at(i) == "8" || m_parts->at(i) == "11" || m_parts->at(i) == "97") {
				schema = atoi(m_parts->at(i).c_str());
				break;
			}
		}

		if (schema != 255) {
			content.push_back("a=sendrecv");
			content.push_back(myformat("a=rtpmap:8 PCMA/%u", samplerate));
			content.push_back(myformat("a=rtpmap:11 L16/%u", samplerate));
			content.push_back(myformat("a=rtpmap:97 speex/%u", samplerate));
			content.push_back("a=fmtp:97 mode=\"1,any\";vbr=on");
			
			int recv_port = u->allocate_port();
	
			content.push_back(myformat("m=audio %d RTP/AVP %u", recv_port, schema));

			std::string content_out = merge(content, "\r\n");

			// merge headers
			std::vector<std::string> hout;
			create_response_headers("SIP/2.0 200 OK", &hout, false, headers, content_out.size(), dst_ip);
			std::string headers_out = merge(hout, "\r\n");

			std::string out = headers_out + "\r\n" + content_out;

			// send INVITE reply
			u->transmit_packet(src_ip, src_port, dst_ip, dst_port, (const uint8_t *)out.c_str(), out.size());

			// find port to transmit rtp data to and start send-thread
			int tgt_rtp_port = m_parts->size() >= 2 ? atoi(m_parts->at(1).c_str()) : 8000;

			sip_session_t *ss = new sip_session_t();
			ss->start_ts = get_us();
			ss->headers = *headers;
			ss->sip_addr_peer = src_ip;
			ss->sip_port_peer = src_port;
			ss->sip_addr_me = dst_ip;
			ss->sip_port_me = dst_port;
			ss->schema = schema;

			std::thread *th = new std::thread(&sip::voicemailbox, this, src_ip, tgt_rtp_port, dst_ip, recv_port, ss, pd);

			slock.lock();
			sessions.insert({ th, ss });
			slock.unlock();
		}

		delete m_parts;
	}
}

std::pair<uint8_t *, int> create_rtp_packet(const uint32_t ssrc, const uint16_t seq_nr, const uint32_t t, const uint8_t schema, const short *const samples, const int n_samples)
{
	int sample_size = 0;

	if (schema == 8)	// a-law
		sample_size = sizeof(uint8_t);
	else if (schema == 11)	// l16 mono
		sample_size = sizeof(uint16_t);
	else if (schema == 97)	// speex
		sample_size = sizeof(uint8_t);
	else {
		dolog(error, "SIP: Invalid rtp payload schema %d\n", schema);
		return { nullptr, 0 };
	}

	size_t size = 3 * 4 + n_samples * sample_size;
	uint8_t *rtp_packet = new uint8_t[size * 2](); // *2 for speex (is this required?)

	rtp_packet[0] |= 128;  // v2
	rtp_packet[1] = schema;  // a-law
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

	if (schema == 8) {	// a-law
		for(int i=0; i<n_samples; i++)
			rtp_packet[12 + i] = encode_alaw(samples[i]);
	}
	else if (schema == 1) {	// l16 mono
		for(int i=0; i<n_samples; i++) {
			rtp_packet[12 + i * 2 + 0] = samples[i] >> 8;
			rtp_packet[12 + i * 2 + 1] = samples[i];
		}
	}
	else if (schema == 97) { // speex
		speex_t spx { 0 };

		spx.state = speex_encoder_init(&speex_nb_mode);

		int tmp = 8; // set the quality to 8 (15 kbps)
		speex_encoder_ctl(spx.state, SPEEX_SET_QUALITY, &tmp);

		// is this required?
		short *input = new short[n_samples];
		memcpy(input, samples, n_samples * sizeof(short));

		speex_bits_reset(&spx.bits);
		speex_encode_int(spx.state, input, &spx.bits);

		size = 12 + speex_bits_write(&spx.bits, (char *)&rtp_packet[12], n_samples);

		delete [] input;

		speex_encoder_destroy(spx.state);
		speex_bits_destroy(&spx.bits);
	}

	return { rtp_packet, size };
}

void sip::send_BYE(const any_addr & tgt_addr, const int tgt_port, const any_addr & src_addr, const int src_port, const std::vector<std::string> & headers)
{
	std::string number = "0";

	auto str_to = find_header(&headers, "To");
	if (str_to.has_value()) {
		std::string::size_type lt = str_to.value().rfind('<');
		std::string::size_type gt = str_to.value().rfind('>');

		number = str_to.value().substr(lt + 1, gt - lt - 1);
	}

	std::vector<std::string> hout;
	create_response_headers(myformat("BYE %s SIP/2.0", number.c_str()), &hout, true, &headers, 0, src_addr);

	std::string out = merge(hout, "\r\n") + "\r\n";

	u->transmit_packet(tgt_addr, tgt_port, src_addr, src_port, (const uint8_t *)out.c_str(), out.size());
}

void sip::voicemailbox(const any_addr & tgt_addr, const int tgt_port, const any_addr & src_addr, const int src_port, sip_session_t *const ss, void *const pd)
{
	set_thread_name("myip-siprtp");

	SF_INFO si { .frames = 0, .samplerate = samplerate, .channels = 1, .format = SF_FORMAT_WAV | SF_FORMAT_PCM_16, .sections = 0, .seekable = 0 };

	time_t start = time(nullptr);

	struct tm tm;
	localtime_r(&start, &tm);

	std::string filename = myformat("%04d-%02d-%02d_%02d-%02d-%02d_%s_%u.wav",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec,
			tgt_addr.to_str().c_str(), tgt_port);

	std::string full_fname = mailbox_path + "/" + filename;

	ss->sf = sf_open(full_fname.c_str(), SFM_WRITE, &si);

	if (ss->sf) {
		std::string merged = merge(ss->headers, "\n");

		int rc = sf_set_string(ss->sf, SF_STR_COMMENT, merged.c_str());
		if (rc)
			dolog(warning, "SIP: cannot add SF_STR_COMMENT to .wav: %s\n", sf_error_number(rc));

		auto str_from = find_header(&ss->headers, "From");
		if (str_from.has_value()) {
			rc = sf_set_string(ss->sf, SF_STR_ARTIST, str_from.value().c_str());

			if (rc)
				dolog(warning, "SIP: cannot add SF_STR_ARTIST to .wav: %s\n", sf_error_number(rc));
		}
	}
	else {
		dolog(error, "SIP: cannot create %s (%s)\n", full_fname.c_str(), strerror(errno));
	}

	u->add_handler(src_port, std::bind(&sip::input_recv, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), ss);

	uint16_t seq_nr = 0;
	uint32_t t = 0;

	uint32_t ssrc;
	get_random((uint8_t *)&ssrc, sizeof ssrc);

	int n_work = n_samples, offset = 0;

	while(n_work > 0 && !stop_flag) {
		int cur_n = std::min(n_work, 500/* must be even */);

		bool odd = cur_n & 1;

		auto rtpp = create_rtp_packet(ssrc, seq_nr, t, ss->schema, &samples[offset], cur_n + odd);

		offset += cur_n;
		n_work -= cur_n;

		t += cur_n;

		seq_nr++;

		if (rtpp.second) {
			u->transmit_packet(tgt_addr, tgt_port, src_addr, src_port, rtpp.first, rtpp.second);

			delete [] rtpp.first;
		}

		double sleep = 1000000.0 / (samplerate / double(cur_n));
		myusleep(sleep);
	}

	// in case the peer starts to send only after the recorded message
	ss->latest_pkt = get_us();

	// session time-out
	while(get_us() - ss->latest_pkt < 5000000l && !stop_flag)
		myusleep(500000);

	send_BYE(ss->sip_addr_peer, ss->sip_port_peer, ss->sip_addr_me, ss->sip_port_me, ss->headers);

	long int took = time(nullptr) - start;
	dolog(info, "SIP: Recording stopped after %lu seconds\n", took);

	stats_add_average(sip_rtp_duration, took);

	u->remove_handler(src_port);

	u->unallocate_port(src_port);

	sf_close(ss->sf);

	ss->finished = true;
}

// from
// http://dystopiancode.blogspot.com/2012/02/pcm-law-and-u-law-companding-algorithms.html
int16_t decode_alaw(int8_t number)
{
	uint8_t sign = 0x00;
	uint8_t position = 0;
	int16_t decoded = 0;

	number^=0x55;

	if (number&0x80) {
		number&=~(1<<7);
		sign = -1;
	}

	position = ((number & 0xF0) >>4) + 4;

	if (position!=4) {
		decoded = ((1<<position)|((number&0x0F)<<(position-4)) |(1<<(position-5)));
	}
	else {
		decoded = (number<<1)|1;
	}

	return sign == 0 ? decoded:-decoded;
}

void sip::input_recv(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, void *const pd)
{
	sip_session_t *ss = static_cast<sip_session_t *>(pd);

	if (!ss->sf)
		return;

	ss->latest_pkt = get_us();

	if (!ss->stats_done) {
		ss->stats_done = true;

		stats_inc_counter(sip_rtp_sessions);

		if (ss->schema == 8)
			stats_inc_counter(sip_rtp_codec_8);
		else if (ss->schema == 11)
			stats_inc_counter(sip_rtp_codec_11);
		else if (ss->schema == 97)
			stats_inc_counter(sip_rtp_codec_97);
	}

	auto pl = p->get_payload();

	if (ss->schema == 8) {  // a-law
		int n_samples = pl.second - 12;

		if (n_samples > 0) {
			short *temp = new short[n_samples];

			for(int i=0; i<n_samples; i++)
				temp[i] = decode_alaw(pl.first[12 + i]);

			int rc = 0;
			if ((rc = sf_write_short(ss->sf, temp, n_samples)) != n_samples)
				dolog(warning, "SIP: short write on WAV-file: %d/%d\n", rc, n_samples);

			delete [] temp;
		}
	}
	else if (ss->schema == 11) { // l16 mono
		int n_samples = (pl.second - 12) / 2;

		if (n_samples > 0) {
			int rc = 0;
			if ((rc = sf_write_short(ss->sf, (const short *)&pl.first[12], n_samples)) != n_samples)
				dolog(warning, "SIP: short write on WAV-file: %d/%d\n", rc, n_samples);
		}
	}
	else if (ss->schema == 97) { // speex
		speex_t spx { 0 };
		speex_bits_init(&spx.bits);
		spx.state = speex_decoder_init(&speex_nb_mode);

		speex_bits_read_from(&spx.bits, (char *)&pl.first[12], pl.second - 12);

		int frame_size = 0;
		speex_decoder_ctl(spx.state, SPEEX_GET_FRAME_SIZE, &frame_size);

		short *of = new short[frame_size];
		speex_decode_int(spx.state, &spx.bits, of);

		int rc = 0;
		if ((rc = sf_write_short(ss->sf, of, frame_size)) != frame_size)
			dolog(warning, "SIP: short write on WAV-file: %d/%d\n", rc, frame_size);

		delete [] of;

		speex_bits_destroy(&spx.bits);
		speex_decoder_destroy(spx.state);
	}
	else {
		dolog(warning, "SIP: unsupported incoming schema %u\n", ss->schema);
	}
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
