// (C) 2022-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <assert.h>
#include <atomic>
#include <climits>
#include <errno.h>
#include <math.h>
#include <set>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "fifo.h"
#include "ipv4.h"
#include "font.h"
#include "log.h"
#include "mqtt_client.h"
#include "stats.h"
#include "tcp.h"
#include "time.h"
#include "types.h"
#include "utils.h"


using namespace std::chrono_literals;

static std::atomic_bool stop { false };

struct frame_buffer_t
{
	std::thread     *th        { nullptr };
	interruptable_sleep terminate;

	int              w         { 0       };
	int              h         { 0       };

        mutable std::mutex fb_lock;
	uint8_t         *buffer    { nullptr };

        mutable std::mutex cb_lock;
	std::set<vnc_session_data *> callbacks;

	mqtt_client       *mc      { nullptr };
	fifo<std::string> *mc_data { nullptr };

	bool has_listeners() const {
		const std::lock_guard<std::mutex> lck(cb_lock);

		return callbacks.empty() == false;
	}

	void register_callback(vnc_session_data *p) {
		DOLOG(ll_info, "register_callback %p\n", p);
		const std::lock_guard<std::mutex> lck(cb_lock);

		auto rc = callbacks.insert(p);
		assert(rc.second);
	}

	void unregister_callback(vnc_session_data *p) {
		DOLOG(ll_info, "unregister_callback %p\n", p);
		const std::lock_guard<std::mutex> lck(cb_lock);

		// may have not been registered if the connection
		// is dropped before then handshake was fully
		// performed
		callbacks.erase(p);
	}

	void callback() {
		const std::lock_guard<std::mutex> lck(cb_lock);

		// DOLOG(ll_debug, "VNC: %zu callbacks\n", callbacks.size());

		for(auto vs : callbacks) {
			const std::lock_guard<std::mutex> lck(vs->w_lock);

			// DOLOG(ll_debug, "VNC: %zu CALLBACK for %s (%p)\n", get_us(), vs->client_addr.c_str(), vs);

			vs->wq.push(new vnc_thread_work_t());

			vs->w_cond.notify_one();
		}
	}
} frame_buffer;

void vnc_thread(session *ts);

void frame_buffer_thread(frame_buffer_t *ts_in);

void vnc_init()
{
	std::unique_lock<std::mutex> lck(frame_buffer.fb_lock);

	if (frame_buffer.buffer == nullptr) {
		frame_buffer.w       = 640;
		frame_buffer.h       = 480;

		size_t n_bytes       = size_t(frame_buffer.w) * size_t(frame_buffer.h) * 3;
		frame_buffer.buffer  = new uint8_t[n_bytes]();

		frame_buffer.th      = new std::thread(frame_buffer_thread, &frame_buffer);

		frame_buffer.mc      = nullptr;

		frame_buffer.mc_data = nullptr;
	}
}

void vnc_set_mqtt_client(mqtt_client *const mc)
{
	std::unique_lock<std::mutex> lck(frame_buffer.fb_lock);

	frame_buffer.mc      = mc;

	frame_buffer.mc_data = frame_buffer.mc->subscribe("vanheusden/bitcoin/bitstamp_usd");
}

void vnc_deinit()
{
	stop = true;

	std::unique_lock<std::mutex> lck(frame_buffer.fb_lock);

	if (frame_buffer.th) {
		frame_buffer.terminate.signal_stop();

		frame_buffer.th->join();
		delete frame_buffer.th;
		frame_buffer.th = nullptr;

		delete [] frame_buffer.buffer;
		frame_buffer.buffer = nullptr;
	}
}

void draw_text(frame_buffer_t *fb_in, int x, int y, const char *const text, const int r, const int g, const int b)
{
	const int maxo = fb_in->w * fb_in->h * 3;
	int       len  = strlen(text);

	for(int i=0; i<len; i++) {
		int c = text[i] & 127;

		for(int cy=0; cy<8; cy++) {
			for(int cx=0; cx<8; cx++) {
				int o = (cy + y) * fb_in -> w * 3 + (x + i * 8 + cx) * 3;
				if (o >= maxo)
					break;

				uint8_t pixel_value = font_8x8[c][cy][cx];

				fb_in->buffer[o + 0] = pixel_value ? r : 0;
				fb_in->buffer[o + 1] = pixel_value ? g : 0;
				fb_in->buffer[o + 2] = pixel_value ? b : 0;
			}
		}
	}
}

void frame_buffer_thread(frame_buffer_t *fb_work)
{
	set_thread_name("myip-framebuf");

	char text[16] { 0 };

	int x  = fb_work->w / 2;
	int y  = fb_work->h / 2;
	int dx = 1;
	int dy = 1;

	uint64_t latest_update = 0;

	std::string latest_btc;

	for(;;) {
		if (fb_work->mc_data) {
			auto rc = fb_work->mc_data->get(1);

			if (rc.has_value())
				latest_btc = "BTC price: " + rc.value();
		}

		// should be locking for these as well

		// bounce
		x += dx;
		y += dy;

		if (x >= fb_work->w) {
			x = fb_work->w - 1;
			dx = -((rand() % 3) + 1);
		}

		if (y >= fb_work->h) {
			y = fb_work->h - 1;
			dy = -((rand() % 3) + 1);
		}

		if (x < 0) {
			x = 0;
			dx = (rand() % 3) + 1;
		}

		if (y < 0) {
			y = 0;
			dy = (rand() % 3) + 1;
		}

		uint64_t now = get_us();

		if (fb_work->has_listeners() && now - latest_update >= 999999) {  // 1 time per second
			fb_work->fb_lock.lock();

			latest_update = now;

			int    subn = (rand() % 5) + 1;

			time_t tnow = time(nullptr);

			tm     tm { 0 };
			gmtime_r(&tnow, &tm);

			for(int y=0; y<fb_work->h; y++) {
				const int o = y * fb_work->w * 3;

				for(int x=0; x<fb_work->w; x++) {
					int ox = o + x * 3;

					if (fb_work->buffer[ox] >= subn)
						fb_work->buffer[ox] -= subn;
				}
			}

			snprintf(text, sizeof text, "%02d:%02d:%02d - MyIP", tm.tm_hour, tm.tm_min, tm.tm_sec);

			draw_text(fb_work, x, y, text, 255, 255, 255);

			draw_text(fb_work, 0, 8, latest_btc.c_str(), 0, 255, 0);

			fb_work->fb_lock.unlock();

			fb_work->callback();
		}

		if (fb_work->terminate.sleep(101))
			break;
	}

	delete [] fb_work->buffer;

	fb_work->buffer = nullptr;
}

void calculate_fb_update(frame_buffer_t *fb, std::vector<int32_t> & encodings, bool incremental, int x, int y, int w, int h, uint8_t depth, uint8_t **message, size_t *message_len, vnc_private_data *vpd, vnc_session_data *const vsd)
{
	if (fb->w < x + w || fb->h < y + h)
		return;

	uint32_t ce = 0;  // RAW is default
	for(int32_t e : encodings) {
		if (e == 6) {  // ZLIB
			ce = e;
			DOLOG(ll_debug, "VNC: zlib encoding\n");
		}
	}

	const std::lock_guard<std::mutex> lck(fb->fb_lock);
	if (!fb->buffer)
		return;

	*message = (uint8_t *)malloc(4 + 12 * 1 + w * h * 4); // at most

	(*message)[0] = 0;  // FramebufferUpdate
	(*message)[1] = 0;  // padding
	(*message)[2] = 0;  // number of rectangles
	(*message)[3] = 1;  //  (1)

	(*message)[4] = x >> 8;  // x
	(*message)[5] = x & 255; 
	(*message)[6] = y >> 8;  // y
	(*message)[7] = y & 255; 
	(*message)[8] = w >> 8;  // w
	(*message)[9] = w & 255; 
	(*message)[10] = h >> 8;  // h
	(*message)[11] = h & 255; 
	(*message)[12] = ce >> 24;  // encoding type
	(*message)[13] = ce >> 16;  // (0 == raw)
	(*message)[14] = ce >>  8;
	(*message)[15] = ce;

	uint8_t *temp = (uint8_t *)malloc(w * h * 3 * 2);
	int otemp = 0;

	if (depth == 32 || depth == 24) {
		for(int yo=y; yo<y + h; yo++) {
			for(int xo=x; xo<x + w; xo++) {
				int offset = yo * w * 3 + xo * 3;

				temp[otemp++] = fb->buffer[offset + 2];  // blue
				temp[otemp++] = fb->buffer[offset + 1];  // green
				temp[otemp++] = fb->buffer[offset + 0];  // red
				temp[otemp++] = 255;  // alpha
			}
		}
	}
	else if (depth == 8) {
		for(int yo=y; yo<y + h; yo++) {
			for(int xo=x; xo<x + w; xo++) {
				int offset = yo * w * 3 + xo * 3;

				temp[otemp++] = (fb->buffer[offset + 0] & 0xe0) |  // red
						((fb->buffer[offset + 1] >> 3) & 0x1c) |  // green
						(fb->buffer[offset + 2] >> 6);  // blue
			}
		}
	}
	else if (depth == 1) {
		uint8_t b_out = 0, b_n = 0;

		for(int yo=y; yo<y + h; yo++) {
			for(int xo=x; xo<x + w; xo++) {
				int offset = yo * w * 3 + xo * 3;

				int gray = (fb->buffer[offset + 0] + fb->buffer[offset + 1] + fb->buffer[offset + 2]) / 3;
				uint8_t bit = gray >= 128;

				b_out <<= 1;
				b_out |= bit;
				b_n++;

				if (b_n == 8) {
					temp[otemp++] = b_out;
					b_n = 0;
				}
			}
		}

		if (b_n) {
			DOLOG(ll_error, "VNC: BITS LEFT: %d\n", b_n);
			stats_inc_counter(vpd->vnc_err);
		}
	}
	else {
		DOLOG(ll_info, "VNC: depth=%d not supported\n", depth);

		stats_inc_counter(vpd->vnc_err);
	}

	int o = 16;

	if (ce == 0) {  // raw
		memcpy(&(*message)[o], temp, otemp);
		o += otemp;
	}
	else if (ce == 6) {  // zlib
		vsd->strm.next_in = temp;
		vsd->strm.avail_in = otemp;
		vsd->strm.next_out = &(*message)[o + 4];
		vsd->strm.avail_out = w * h * 3 * 2;

		if (deflate(&vsd->strm, Z_SYNC_FLUSH) != Z_OK)
			DOLOG(ll_warning, "VNC: deflate failed\n");

		uint32_t size = vsd->strm.total_out - vsd->prev_zsize;
		(*message)[o + 0] = size >> 24;
		(*message)[o + 1] = size >> 16;
		(*message)[o + 2] = size >>  8;
		(*message)[o + 3] = size;

		o += size + 4;

		vsd->prev_zsize = vsd->strm.total_out;
	}
	else {
		DOLOG(ll_error, "VNC: unknown encoding type %d\n", ce);
	}

	free(temp);

	*message_len = o;
}

bool vnc_new_session(pstream *const ps, session *const s)
{
	vnc_session_data *vs = new vnc_session_data();

	any_addr src_addr = s->get_their_addr();
	vs->client_addr   = src_addr.to_str();

	vs->buffer        = nullptr;
	vs->buffer_size   = 0;

	vs->state         = vs_initial_handshake_server_send;

	vs->depth         = 32;

	vs->start         = time(nullptr);

	vs->vpd           = dynamic_cast<vnc_private_data *>(s->get_application_private_data());
	stats_inc_counter(vs->vpd->vnc_requests);

	s->set_callback_private_data(vs);

	DOLOG(ll_debug, "VNC: new session with %s\n", vs->client_addr.c_str());

	vs->strm.zalloc   = 0;
	vs->strm.zfree    = 0;
	vs->strm.opaque   = 0;
	if (deflateInit(&vs->strm, Z_DEFAULT_COMPRESSION) != Z_OK)
		DOLOG(ll_warning, "VNC: zlib init failed\n");

	vs->th            = new std::thread(vnc_thread, s);

	return true;
}

bool vnc_new_data(pstream *const ps, session *const s, buffer_in data)
{
	vnc_session_data *vs = dynamic_cast<vnc_session_data *>(s->get_callback_private_data());

	if (!vs) {
		DOLOG(ll_info, "VNC: Data for a non-existing session\n");
		return false;
	}

	int data_len = data.get_n_bytes_left();

	if (data_len == 0) {
		DOLOG(ll_debug, "VNC: client closed session\n");
		vs->w_cond.notify_one();
		return true;
	}

	vnc_thread_work_t *work = new vnc_thread_work_t;
	work->data     = reinterpret_cast<char *>(duplicate(reinterpret_cast<const uint8_t *>(data.get_bytes(data_len)), data_len));
	work->data_len = data_len;

	const std::lock_guard<std::mutex> lck(vs->w_lock);
	vs->wq.push(work);
	vs->w_cond.notify_one();

	return true;
}

void vnc_thread(session *ts)
{
	set_thread_name("myip-vnc");

	vnc_session_data *vs  = dynamic_cast<vnc_session_data *>(ts->get_callback_private_data());
	vnc_private_data *vpd = vs->vpd;
	bool rc = true, first = true;

	std::vector<int32_t> encodings;
	encodings.push_back(0);  // at least raw

	int n_encodings = -1;
	bool continuous_updates = false;

	int running_cmd = -1, ignore_data_n = -1;

	for(;vs->state != vs_terminate && !stop;) {
		bool cont_or_initial_upd_frame = false;
		vnc_thread_work_t *work = nullptr;

		if (!first)
		{
			std::unique_lock<std::mutex> lck(vs->w_lock);

			for(;vs->state != vs_terminate && !stop;) {
				if (vs->wq.empty() == false) {
					work = vs->wq.front();
					vs->wq.pop();
					break;
				}

				vs->w_cond.wait_for(lck, 500ms);
			}
		}

		if (first)
			first = false;
		else {
			if (!work) {
				DOLOG(ll_info, "VNC: TERMINATE THREAD REQUESTED\n");
				break;
			}

			if (work->data_len == 0) {  // callback asked for update
				if (continuous_updates)
					cont_or_initial_upd_frame = true;
			}
			else {
				vs->buffer = (char *)realloc(vs->buffer, vs->buffer_size + work->data_len);

				memcpy(&vs->buffer[vs->buffer_size], work->data, work->data_len);
				vs->buffer_size += work->data_len;
			}
		}

		DOLOG(ll_debug, "VNC: state: %d\n", vs->state);

		if (vs->state == vs_initial_handshake_server_send) {
			const char initial_message[] = "RFB 003.008\n";

			DOLOG(ll_debug, "VNC: send handshake of 12 bytes\n");
			ts->get_stream_target()->send_data(ts, (const uint8_t *)initial_message, 12);  // must be 12 bytes

			vs->state = vs_initial_handshake_client_resp;
		}
	
		if (vs->state == vs_initial_handshake_client_resp) {
			char *handshake = (char *)get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 12);

			if (handshake) {
				std::string handshake_str = std::string(handshake, 12);

				if (memcmp(handshake, "RFB", 3) == 0) {  // let's not be too picky
					DOLOG(ll_debug, "VNC: Client responded with protocol version: %s\n", handshake_str.c_str());
					vs->state = vs_security_handshake_server;
				}
				else {
					rc = false;
					DOLOG(ll_info, "VNC: Unexpected/invalid protocol version: %s\n", handshake_str.c_str());
					stats_inc_counter(vpd->vnc_err);
				}

				free(handshake);
			}
		}

		if (vs->state == vs_security_handshake_server) {
			uint8_t message[] = { 1,  // number of security types
				1,  // 'None'
			};

			DOLOG(ll_debug, "VNC: ack security types, %zu bytes\n", sizeof message);
			ts->get_stream_target()->send_data(ts, message, sizeof message);

			vs->state = vs_security_handshake_client_resp;
		}

		if (vs->state == vs_security_handshake_client_resp) {
			uint8_t *chosen_sec = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 1);

			if (chosen_sec) {
				if (*chosen_sec == 1) {  // must have chosen security type 'None'
					uint8_t response[] = { 0, 0, 0, 0 };  // OK
					DOLOG(ll_debug, "VNC: Valid security type chosen, %zu bytes\n", sizeof response);
					ts->get_stream_target()->send_data(ts, response, sizeof response);

					vs->state = vs_client_init;
				}
				else {
					rc = false;

					uint8_t response[] = { 0, 0, 0, 1 };  // failed
					DOLOG(ll_info, "VNC: Unexpected/invalid security type: %d (%zu bytes)\n", *chosen_sec, sizeof response);
					ts->get_stream_target()->send_data(ts, response, sizeof response);
					stats_inc_counter(vpd->vnc_err);
				}

				free(chosen_sec);
			}
		}

		if (vs->state == vs_client_init) {
			uint8_t *client_init = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 1);

			if (client_init) {
				DOLOG(ll_debug, "VNC: client asks for %sdesktop sharing\n", *client_init ? "" : "NO ");

				vs->state = vs_server_init;

				free(client_init);
			}
		}

		if (vs->state == vs_server_init) {  // 7.3.2
			uint8_t message[] = {
				uint8_t(frame_buffer.w >> 8), uint8_t(frame_buffer.w & 255),
				uint8_t(frame_buffer.h >> 8), uint8_t(frame_buffer.h & 255),
				// PIXEL_FORMAT
				32,  // bits per pixel
				24,  // depth
				1,  // big-endian flag
				1,  // true color flag
				0, 255,  // red max
				0, 255,  // green max
				0, 255,  // blue max
				16,  // red shift
				8,  // green shift
				0,  // blue shift (note that alpha is stored in the lowest byte)
				0, 0, 0,
				// name length/string
				0, 0, 0, 4,
				'M', 'y', 'I', 'P'  // no "..."! that would include a 0x00!
			};

			DOLOG(ll_debug, "VNC: server init, %zu bytes\n", sizeof message);
			ts->get_stream_target()->send_data(ts, message, sizeof message);

			frame_buffer.register_callback(vs);

			vs->state = vs_running_waiting_cmd;
		}

		if (cont_or_initial_upd_frame) {
			// send initial frame
			uint8_t *fb_message = nullptr;
			size_t fb_message_len = 0;
			calculate_fb_update(&frame_buffer, encodings, false, 0, 0, frame_buffer.w, frame_buffer.h, 24, &fb_message, &fb_message_len, vpd, vs);

			DOLOG(ll_debug, "VNC: intial (full) framebuffer update (%zu bytes)\n", fb_message_len);

			ts->get_stream_target()->send_data(ts, fb_message, fb_message_len);
			free(fb_message);
		}

		if (vs->state == vs_running_waiting_cmd) {
			uint8_t *cmd = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 1);

			if (cmd) {
				running_cmd = *cmd;

				DOLOG(ll_debug, "VNC: Received command %d\n", running_cmd);

				vs->state = vs_running_waiting_data;

				free(cmd);
			}
		}

		if (vs->state == vs_running_waiting_data) {
			bool proceed = false;
			int ignore_n = 0;

			DOLOG(ll_debug, "VNC: waiting for data for command %d\n", running_cmd);

			if (running_cmd == 0) {  // SetPixelFormat, 7.5.1
				DOLOG(ll_debug, "VNC: Retrieving pixelformat\n");

				uint8_t *pf = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 19);

				if (pf) {
					const uint8_t *data = &pf[3];  // skip padding

					vs->depth = data[1];

					uint16_t rmax = (data[4] << 8) | data[5];
					uint16_t gmax = (data[6] << 8) | data[7];
					uint16_t bmax = (data[8] << 8) | data[9];

					DOLOG(ll_debug, "VNC: Changed 'depth' (BPP) to %d (bpp: %d, red/green/blue max: %d/%d/%d)\n", vs->depth, data[0], rmax, gmax, bmax);

					vs->state = vs_running_waiting_cmd;

					free(pf);
				}
			}
			else if (running_cmd == 2) {  // SetEncodings, 7.5.2
				uint8_t *parameters = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 3);

				if (parameters) {
					n_encodings = (parameters[1] << 8) | parameters[2];
					DOLOG(ll_debug, "VNC: Retrieving number of encodings (%d)\n", n_encodings);

					vs->state = vs_running_waiting_data_extra;

					free(parameters);
				}
			}
			else if (running_cmd == 3) {  // FramebufferUpdateRequest
				uint8_t *parameters = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 9);

				if (parameters) {
					uint8_t *message = nullptr;
					size_t message_len = 0;

					bool incremental = parameters[0];
					int x = (parameters[1] << 8) | parameters[2];
					int y = (parameters[3] << 8) | parameters[4];
					int w = (parameters[5] << 8) | parameters[6];
					int h = (parameters[7] << 8) | parameters[8];

					calculate_fb_update(&frame_buffer, encodings, incremental, x, y, w, h, vs->depth, &message, &message_len, vpd, vs);

					DOLOG(ll_debug, "VNC: framebuffer update %zu bytes for %dx%d at %d,%d: %zu bytes%s\n", message_len, w, h, x, y, message_len, incremental?" (incremental)":"");

					ts->get_stream_target()->send_data(ts, message, message_len);

					free(message);

					free(parameters);

					proceed = true;
				}
			}
			else if (running_cmd == 4) {  // KeyEvent
				ignore_n = 7;
				DOLOG(ll_debug, "VNC: CLIENT KeyEvent (ignore %d)\n", ignore_n);
			}
			else if (running_cmd == 5) {  // PointerEvent
				ignore_n = 5;
				DOLOG(ll_debug, "VNC: CLIENT PointerEvent (ignore %d)\n", ignore_n);
			}
			else if (running_cmd == 6) {  // ClientCutText
				uint8_t *parameters = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 7);

				if (parameters) {
					ignore_data_n = (parameters[3] << 24) | (parameters[4] << 16) | (parameters[5] << 8) | parameters[6];
					DOLOG(ll_debug, "VNC: ClientCutText (ignore %d)\n", ignore_data_n);

					vs->state = vs_running_waiting_data_ignore;

					free(parameters);
				}
			}
			else {
				DOLOG(ll_warning, "VNC: Command %d not known (data state)\n", running_cmd);
				stats_inc_counter(vpd->vnc_err);
				rc = false;
			}

			// part of the command
			if (ignore_n) {
				DOLOG(ll_debug, "VNC: Ignore %d bytes from command\n", ignore_n);

				uint8_t *ignore = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, ignore_n);

				if (ignore) {
					free(ignore);
					proceed = true;
				}
			}

			if (proceed) {
				vs->state = vs_running_waiting_cmd;

				running_cmd = -1;
			}
		}

		// parameters of a command to ignore
		if (vs->state == vs_running_waiting_data_ignore) {
			DOLOG(ll_debug, "VNC: Ignore %d command parameters\n", ignore_data_n);

			assert(ignore_data_n > 0);
			uint8_t *ignore = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, ignore_data_n);

			if (ignore) {
				vs->state = vs_running_waiting_cmd;

				ignore_data_n = -1;

				free(ignore);
			}
		}

		if (vs->state == vs_running_waiting_data_extra) {
			if (running_cmd == 2) {  // SetEncodings
				DOLOG(ll_debug, "VNC: Retrieving %d encodings\n", n_encodings);

				uint8_t *encodings_bin = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, n_encodings * 4);

				if (encodings_bin) {
					encodings.clear();

					continuous_updates = false;

					for(int i=0; i<n_encodings; i++) {
						int o = i * 4;
						int32_t e = (encodings_bin[o + 0] << 24) | (encodings_bin[o + 1] << 16) | (encodings_bin[o + 2] << 8) | encodings_bin[o + 3];
						encodings.push_back(e);

						DOLOG(ll_debug, "VNC: encoding %d: %d\n", i, e);

						if (e == -313)
							continuous_updates = true;
					}

					n_encodings = -1;

					vs->state = vs_running_waiting_cmd;

					free(encodings_bin);
				}
			}
			else {
				DOLOG(ll_warning, "VNC: Command %d not known (data-extra state)\n", running_cmd);
				stats_inc_counter(vpd->vnc_err);
				rc = false;
			}
		}

		if (!rc)
			vs->state = vs_terminate;

		if (work) {
			delete [] work->data;
			delete work;
		}
	}

	ts->get_stream_target()->end_session(ts);

	frame_buffer.unregister_callback(vs);

	DOLOG(ll_info, "VNC: Thread terminating for %s\n", vs->client_addr.c_str());
}

bool vnc_close_session_1(pstream *const ps, session *const s)
{
	return true;
}

bool vnc_close_session_2(pstream *const ps, session *const s)
{
	session_data *const sd = s->get_callback_private_data();

	if (sd) {
		vnc_session_data *vs = dynamic_cast<vnc_session_data *>(sd);

		vs->state = vs_terminate;

		{
			const std::lock_guard<std::mutex> lck(vs->w_lock);
			vs->wq.push(nullptr);
			vs->w_cond.notify_one();
		}

		stats_add_average(vs->vpd->vnc_duration, time(nullptr) - vs->start);

		vs->th->join();
		delete vs->th;

		free(vs->buffer);

		deflateEnd(&vs->strm);

		delete vs;

		s->set_callback_private_data(nullptr);
	}

	return true;
}

port_handler_t vnc_get_handler(stats *const s)
{
	port_handler_t stream_vnc;

	stream_vnc.init             = vnc_init;
	stream_vnc.new_session      = vnc_new_session;
	stream_vnc.new_data         = vnc_new_data;
	stream_vnc.session_closed_1 = vnc_close_session_1;
	stream_vnc.session_closed_2 = vnc_close_session_2;
	stream_vnc.deinit           = vnc_deinit;

	vnc_private_data *vpd = new vnc_private_data();

	// 1.3.6.1.4.1.57850.1.2: vnc
	vpd->vnc_requests = s->register_stat("vnc_requests", "1.3.6.1.4.1.57850.1.2.1");
	vpd->vnc_err      = s->register_stat("vnc_err", "1.3.6.1.4.1.57850.1.2.2");
	vpd->vnc_duration = s->register_stat("vnc_duration", "1.3.6.1.4.1.57850.1.2.3");

	stream_vnc.pd = vpd;

	return stream_vnc;
}
