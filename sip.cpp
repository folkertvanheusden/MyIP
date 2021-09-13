// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <math.h>
#include <optional>
#include <samplerate.h>
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

void resample(const short *const in, const int in_rate, const int n_samples, short **const out, const int out_rate, int *const out_n_samples)
{
	float *in_float = new float[n_samples];
	src_short_to_float_array(in, in_float, n_samples);

	double ratio = out_rate / double(in_rate);
	*out_n_samples = n_samples * ratio;
	float *out_float = new float[*out_n_samples];

	SRC_DATA sd;
	sd.data_in = in_float;
	sd.data_out = out_float;
	sd.input_frames = n_samples;
	sd.output_frames = *out_n_samples;
	sd.input_frames_used = 0;
	sd.output_frames_gen = 0;
	sd.end_of_input = 0;
	sd.src_ratio = ratio;

	int rc = -1;
	if ((rc = src_simple(&sd, SRC_SINC_BEST_QUALITY, 1)) != 0)
		dolog(warning, "SIP: resample failed: %s", src_strerror(rc));

	*out = new short[*out_n_samples];
	src_float_to_short_array(out_float, *out, *out_n_samples);

	delete [] out_float;

	delete [] in_float;
}

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

sip::sip(stats *const s, udp *const u, const std::string & sample, const std::string & mailbox_path, const std::string & upstream_sip_server, const std::string & upstream_sip_user, const std::string & upstream_sip_password, const any_addr & myip, const int myport, const int interval) :
	u(u),
	mailbox_path(mailbox_path),
	upstream_server(upstream_sip_server), username(upstream_sip_user), password(upstream_sip_password),
	myip(myip), myport(myport),
	interval(interval)
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

	th2 = new std::thread(&sip::register_thread, this);
}

sip::~sip()
{
	stop_flag = true;

	th2->join();
	delete th2;

	th->join();
	delete th;

	delete [] samples;
}

void sip::input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, void *const pd)
{
	dolog(info, "SIP: packet from [%s]:%u\n", src_ip.to_str().c_str(), src_port);

	auto pl = p->get_payload();

	if (pl.second == 0) {
		dolog(info, "SIP: empty packet from [%s]:%u\n", src_ip.to_str().c_str(), src_port);
		return;
	}

	u->update_port_ts(dst_port);

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
	else if (parts->size() == 3 && parts->at(0) == "SIP/2.0" && parts->at(1) == "401") {
		reply_to_UNAUTHORIZED(src_ip, src_port, dst_ip, dst_port, header_lines, pd);
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

		if (lt != std::string::npos && gt != std::string::npos) {
			std::string contact = str_to.value().substr(lt, gt - lt + 1);

			target->push_back(myformat("Contact: %s", contact.c_str()));
		}
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
	content.push_back(myformat("a=rtpmap:97 speex/%u", samplerate));
	content.push_back("a=fmtp:97 mode=\"1,any\";vbr=on");

	std::string content_out = merge(content, "\r\n");

	std::vector<std::string> hout;
	create_response_headers("SIP/2.0 200 OK", &hout, false, headers, content_out.size(), dst_ip);
	std::string headers_out = merge(hout, "\r\n");

	std::string out = headers_out + "\r\n" + content_out;

	u->transmit_packet(src_ip, src_port, dst_ip, dst_port, (const uint8_t *)out.c_str(), out.size());
}

codec_t chose_schema(const std::vector<std::string> *const body, const int max_rate)
{
	codec_t best { 255, "", -1 };

	for(std::string line : *body) {
		if (line.substr(0, 9) != "a=rtpmap:")
			continue;

		std::string pars = line.substr(9);

		std::size_t lspace = pars.find(' ');
		if (lspace == std::string::npos)
			continue;

		std::string type_rate = pars.substr(lspace + 1);

		std::size_t slash = type_rate.find('/');
		if (slash == std::string::npos)
			continue;

		uint8_t id = atoi(pars.substr(0, lspace).c_str());

		std::string name = str_tolower(type_rate.substr(0, slash));
		int rate = atoi(type_rate.substr(slash + 1).c_str());

		bool pick = false;

		if (rate >= max_rate && (name == "l16" || name.substr(0, 5) == "speex" || name == "alaw")) {
			if (abs(rate - max_rate) < abs(rate - best.rate) || best.rate == -1)
				pick = true;
		}
		else if (rate == best.rate) {
			if (name == "l16")
				pick = true;
			else if (name != "l16" && name.substr(0, 5) == "speex")
				pick = true;
			else if (best.id == 255)
				pick = true;
		}

		if (pick) {
			best.rate = rate;
			best.id = id;
			best.name = name;
		}
	}

	if (best.id == 255) {
		best.id = 8;
		best.name = "alaw";  // safe choice
		best.rate = 8000;
	}

	if (best.name.substr(0, 5) == "speex") {
		void *enc_state = speex_encoder_init(&speex_nb_mode);
		speex_encoder_ctl(enc_state,SPEEX_GET_FRAME_SIZE, &best.frame_size);
		speex_encoder_destroy(enc_state);
	}
	else {
		best.frame_size = 500;
	}

	dolog(info, "SIP: CODEC chosen: %s/%d (id: %u), frame size: %d\n", best.name.c_str(), best.rate, best.id, best.frame_size);

	return best;
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

		codec_t schema = chose_schema(body, samplerate);

		if (schema.id != 255) {
			content.push_back("a=sendrecv");
			content.push_back(myformat("a=rtpmap:%u %s/%u", schema.id, schema.name.c_str(), schema.rate));

			if (schema.name.substr(0, 5) == "speex")
				content.push_back(myformat("a=fmtp:%u mode=\"1,any\";vbr=on", schema.id));
			
			int recv_port = u->allocate_port();
	
			content.push_back(myformat("m=audio %d RTP/AVP %u", recv_port, schema.id));

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

void sip::reply_to_UNAUTHORIZED(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers, void *const pd)
{
	auto str_wa = find_header(headers, "WWW-Authenticate");
	if (!str_wa.has_value()) {
		dolog(info, "SIP: \"WWW-Authenticate\" missing");
		return;
	}

	std::string work = replace(str_wa.value(), ",", " ");

	std::vector<std::string> *parameters = split(work, " ");

	std::string digest_alg = "MD5";
	auto str_da = find_header(parameters, "algorithm", "=");
	if (str_da.has_value())
		digest_alg = str_da.value();

	std::string realm = "";
	auto str_realm = find_header(parameters, "realm", "=");
	if (str_realm.has_value())
		realm = replace(str_realm.value(), "\"", "");

	std::string nonce = "";
	auto str_nonce = find_header(parameters, "nonce", "=");
	if (str_nonce.has_value())
		nonce = replace(str_nonce.value(), "\"", "");

	std::string a1 = md5hex(username + ":" + realm + ":" + password);
	std::string a2 = md5hex("REGISTER:sip:" + src_ip.to_str());

	std::string digest = md5hex(a1 + ":" + nonce + ":" + a2);

	std::string authorize = "Authorization: Digest username=\"" + username + "\" realm=\"" + realm + "\" nonce=\"" + nonce + "\" uri=\"sip:" + src_ip.to_str() + "\" algorithm=MD5 response=\"" + digest + "\"";

	send_REGISTER(authorize);

	delete parameters;
}

std::pair<uint8_t *, int> create_rtp_packet(const uint32_t ssrc, const uint16_t seq_nr, const uint32_t t, const codec_t & schema, const short *const samples, const int n_samples)
{
	int sample_size = 0;

	if (schema.name == "alaw")// a-law
		sample_size = sizeof(uint8_t);
	else if (schema.name == "l16")	// l16 mono
		sample_size = sizeof(uint16_t);
	else if (schema.name.substr(0, 5) == "speex")	// speex
		sample_size = sizeof(uint8_t);
	else {
		dolog(error, "SIP: Invalid rtp payload schema %s/%d\n", schema.name.c_str(), schema.rate);
		return { nullptr, 0 };
	}

	size_t size = 3 * 4 + n_samples * sample_size;
	uint8_t *rtp_packet = new uint8_t[size * 2](); // *2 for speex (is this required?)

	rtp_packet[0] |= 128;  // v2
	rtp_packet[1] = schema.id;  // a-law
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

	if (schema.name == "alaw") {	// a-law
		for(int i=0; i<n_samples; i++)
			rtp_packet[12 + i] = encode_alaw(samples[i]);
	}
	else if (schema.name == "l16") {	// l16 mono
		for(int i=0; i<n_samples; i++) {
			rtp_packet[12 + i * 2 + 0] = samples[i] >> 8;
			rtp_packet[12 + i * 2 + 1] = samples[i];
		}
	}
	else if (schema.name.substr(0, 5) == "speex") { // speex
		speex_t spx { 0 };

		speex_bits_init(&spx.bits);
		speex_bits_reset(&spx.bits);

		spx.state = speex_encoder_init(&speex_nb_mode);

		int tmp = 10;
		speex_encoder_ctl(spx.state, SPEEX_SET_QUALITY, &tmp);

		// is this required?
		short *input = new short[n_samples];
		memcpy(input, samples, n_samples * sizeof(short));

		speex_encode_int(spx.state, input, &spx.bits);

		size_t new_size = 12 + speex_bits_write(&spx.bits, (char *)&rtp_packet[12], size - 12);

		delete [] input;

		speex_encoder_destroy(spx.state);
		speex_bits_destroy(&spx.bits);

		if (new_size > size) {
			dolog(error, "SIP: speex decoded data too big (%ld > %ld)\n", new_size, size);
			delete [] rtp_packet;
			return { nullptr, 0 };
		}

		size = new_size;
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

		if (lt != std::string::npos && gt != std::string::npos)
			number = str_to.value().substr(lt + 1, gt - lt - 1);
	}

	std::vector<std::string> hout;
	create_response_headers(myformat("BYE %s SIP/2.0", number.c_str()), &hout, true, &headers, 0, src_addr);

	std::string out = merge(hout, "\r\n") + "\r\n";

	u->transmit_packet(tgt_addr, tgt_port, src_addr, src_port, (const uint8_t *)out.c_str(), out.size());
}

void sip::transmit_audio(const any_addr & tgt_addr, const int tgt_port, const any_addr & src_addr, const int src_port, sip_session_t *const ss, const short *const audio, const int n_audio, uint16_t *const seq_nr, uint32_t *const t, const uint32_t ssrc)
{
	int n_work = n_audio, offset = 0;

	while(n_work > 0 && !stop_flag) {
		int cur_n = 0;
		int cur_n_before = std::min(n_work, ss->schema.frame_size);
		std::pair<uint8_t *, int> rtpp;

		if (samplerate != ss->schema.rate) {
			short *resampled = nullptr;
			resample(&audio[offset], samplerate, cur_n_before, &resampled, ss->schema.rate, &cur_n);

			bool odd = cur_n & 1;
			rtpp = create_rtp_packet(ssrc, *seq_nr, *t, ss->schema, &audio[offset], cur_n + odd);

			delete [] resampled;
		}
		else {
			bool odd = cur_n_before & 1;
			rtpp = create_rtp_packet(ssrc, *seq_nr, *t, ss->schema, &audio[offset], cur_n_before + odd);

			cur_n = cur_n_before;
		}

		offset += cur_n_before;
		n_work -= cur_n_before;

		(*t) += cur_n;

		(*seq_nr)++;

		if (rtpp.second) {
			u->transmit_packet(tgt_addr, tgt_port, src_addr, src_port, rtpp.first, rtpp.second);

			delete [] rtpp.first;
		}

		double sleep = 1000000.0 / (samplerate / double(cur_n_before));
		myusleep(sleep);
	}
}

void generate_beep(const double f, const double duration, const int samplerate, short **const beep, size_t *const beep_n)
{
	*beep_n = samplerate * duration;
	*beep = new short[*beep_n];

	double mul = 2.0 * M_PI * f;

	for(size_t i=0; i<*beep_n; i++)
		(*beep)[i] = 32767 * sin(mul * (i + i / double(*beep_n)));
}

void sip::voicemailbox(const any_addr & tgt_addr, const int tgt_port, const any_addr & src_addr, const int src_port, sip_session_t *const ss, void *const pd)
{
	set_thread_name("myip-siprtp");

	SF_INFO si;
	si.frames = 0;
	si.samplerate = ss->schema.rate;
	si.channels = 1;
	si.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;
	si.sections = 0;
	si.seekable = 0;

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

	transmit_audio(tgt_addr, tgt_port, src_addr, src_port, ss, samples, n_samples, &seq_nr, &t, ssrc);

	short *beep = nullptr;
	size_t beep_n = 0;
	generate_beep(825, 0.9, ss->schema.rate, &beep, &beep_n);

	transmit_audio(tgt_addr, tgt_port, src_addr, src_port, ss, beep, beep_n, &seq_nr, &t, ssrc);

	delete [] beep;

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

		if (ss->schema.name == "alaw")
			stats_inc_counter(sip_rtp_codec_8);
		else if (ss->schema.name == "l16")
			stats_inc_counter(sip_rtp_codec_11);
		else if (ss->schema.name.substr(0, 5) == "speex")
			stats_inc_counter(sip_rtp_codec_97);
	}

	auto pl = p->get_payload();

	if (ss->schema.name == "alaw") {  // a-law
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
	else if (ss->schema.name == "l16") { // l16 mono
		int n_samples = (pl.second - 12) / 2;

		if (n_samples > 0) {
			int rc = 0;
			if ((rc = sf_write_short(ss->sf, (const short *)&pl.first[12], n_samples)) != n_samples)
				dolog(warning, "SIP: short write on WAV-file: %d/%d\n", rc, n_samples);
		}
	}
	else if (ss->schema.name.substr(0, 5) == "speex") { // speex
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
		dolog(warning, "SIP: unsupported incoming schema %s/%d\n", ss->schema.name.c_str(), ss->schema.rate);
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

bool sip::send_REGISTER(const std::string & authorize)
{
	std::string work = upstream_server;

	any_addr tgt_addr;
	int tgt_port = 5060;

	std::string::size_type colon = work.find(':');
	if (colon != std::string::npos) {
		tgt_port = atoi(work.substr(colon + 1).c_str());
		work = work.substr(0, colon);
	}

	tgt_addr = parse_address(work.c_str(), 4, ".", 10);

	std::string out;
	out += "REGISTER sip:" + tgt_addr.to_str() + " SIP/2.0\r\n";
	out += "CSeq: 1 REGISTER\r\n";
	out += "Via: SIP/2.0/UDP " + myip.to_str() + ":" + myformat("%d", myport) + "\r\n";
	out += "User-Agent: MyIP\r\n";
	out += "From: <sip:" + username + "@" + tgt_addr.to_str() + ">;tag=277FD9F0-2607D15D\r\n"; // TODO
	out += "Call-ID: e4ec6031-99e1\r\n"; // TODO
	out += "To: <sip:" + username + "@" + tgt_addr.to_str() + ">\r\n";
	out += "Contact: <sip:" + username + "@" + myip.to_str() + ">;q=1\r\n";
	out += "Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,REFER,MESSAGE,INFO,PING\r\n";
	if (!authorize.empty())
		out += authorize + "\r\n";
	out += "Expires: 60\r\n";
	out += "Content-Length: 0\r\n";
	out += "Max-Forwards: 70\r\n\r\n";

	return u->transmit_packet(tgt_addr, tgt_port, myip, myport, (const uint8_t *)out.c_str(), out.size());
}

void sip::register_thread()
{
	while(!stop_flag) {
		if (send_REGISTER("")) {
			for(int i=0; i<interval * 2 && !stop_flag; i++)
				myusleep(500 * 1000);
		}
		else {
			myusleep(30 * 1000 * 1000);
		}
	}
}
