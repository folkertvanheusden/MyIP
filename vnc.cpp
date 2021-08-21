// (C) 2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <climits>
#include <errno.h>
#include <queue>
#include <set>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tcp.h"
#include "utils.h"
#include "ipv4.h"
#include "font.h"
#include "types.h"

struct frame_buffer_t
{
	std::thread *th;

	int w, h;

        mutable std::mutex fb_lock;
	uint8_t *buffer;
} fb;

void vnc_thread(void *ts_in);

void frame_buffer_thread(void *ts_in);

void vnc_init()
{
	fb.w = 256;
	fb.h = 48;

	size_t n_bytes = fb.w * fb.h * 3;
	fb.buffer = new uint8_t[n_bytes];
	memset(fb.buffer, 0x00, n_bytes);

	fb.th = new std::thread(frame_buffer_thread, &fb);
}

void draw_text(frame_buffer_t *fb, int x, int y, const char *text)
{
	int len = strlen(text);

	for(int i=0; i<len; i++) {
		int c = text[i] & 127;

		for(int cy=0; cy<8; cy++) {
			for(int cx=0; cx<8; cx++) {
				int o = (cy + y) * fb -> w * 3 + (x + i * 8 + cx) * 3;

				uint8_t pixel_value = font_8x8[c][cy][cx];

				fb->buffer[o + 0] = pixel_value;
				fb->buffer[o + 1] = pixel_value;
				fb->buffer[o + 2] = pixel_value;
			}
		}
	}
}

void frame_buffer_thread(void *fb_in)
{
	set_thread_name("framebuf");

	frame_buffer_t *fb_work = reinterpret_cast<frame_buffer_t *>(fb_in);

	int x = fb_work->w / 2, y = fb_work->h / 2;
	int dx = 1, dy = 1;

	uint64_t latest_update = 0;

	for(;;) {  // FIXME terminate if requested
		// should be locking for these as well

		// increase green
		assert(x < fb_work->w);
		assert(y < fb_work->h);
		fb_work->buffer[y * fb_work->w * 3 + x * 3 + 1]++;

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

		// increase red
		int cx = rand() % fb_work -> w;
		int cy = rand() % fb_work -> h;
		fb_work->buffer[cy * fb_work->w * 3 + cx * 3 + 0]++;

		uint64_t now = get_us();

		if (now - latest_update >= 1000000) {  // 1 time per second
			fb_work->fb_lock.lock();

			dolog("VNC: %zu FB UPDATE\n", now);
			latest_update = now;

			time_t tnow = time(nullptr);
			struct tm *tm = gmtime(&tnow);

			char *text = nullptr;
			asprintf(&text, "%02d:%02d:%02d - MyIP", tm->tm_hour, tm->tm_min, tm->tm_sec);

			draw_text(fb_work, fb_work->w / 2 - 15 * 8 / 4, fb_work->h / 2 - 8 / 2, text);

			free(text);

			fb_work->fb_lock.unlock();
		}

		usleep(1000);  // ignore any errors during usleep
	}

	delete [] fb_work->buffer;
}

void calculate_fb_update(frame_buffer_t *fb, std::vector<int32_t> & encodings, bool incremental, int x, int y, int w, int h, uint8_t depth, uint8_t **message, size_t *message_len)
{
	if (fb->w < x + w || fb->h < y + h)
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
	(*message)[12] = 0;  // encoding type
	(*message)[13] = 0;  // (0 Raw)
	(*message)[14] = 0;
	(*message)[15] = 0;

	int o = 16;

	fb->fb_lock.lock();

	if (depth == 32 || depth == 24) {
		for(int yo=y; yo<y + h; yo++) {
			for(int xo=x; xo<x + w; xo++) {
				int offset = yo * w * 3 + xo * 3;

				(*message)[o++] = fb->buffer[offset + 2];  // blue
				(*message)[o++] = fb->buffer[offset + 1];  // green
				(*message)[o++] = fb->buffer[offset + 0];  // red
				(*message)[o++] = 255;  // alpha
			}
		}
	}
	else if (depth == 8) {
		for(int yo=y; yo<y + h; yo++) {
			for(int xo=x; xo<x + w; xo++) {
				int offset = yo * w * 3 + xo * 3;

				(*message)[o++] = (fb->buffer[offset + 0] & 0xe0) |  // red
						  (fb->buffer[offset + 1] >> 3) |  // green
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
					(*message)[o++] = b_out;
					b_n = 0;
				}
			}
		}

		if (b_n)
			dolog("VNC: BITS LEFT: %d\n", b_n);
	}
	else {
		dolog("VNC: depth=%d not supported\n", depth);
	}

	fb->fb_lock.unlock();

	*message_len = o;
}

bool vnc_new_session(tcp_session_t *ts, const packet *pkt, void *private_data)
{
	vnc_session_data *vs = new vnc_session_data();

	std::pair<const uint8_t *, int> src_addr = pkt->get_src_addr();
	vs->client_addr = ip_to_str(src_addr);

	vs->buffer = nullptr;
	vs->buffer_size = 0;

	vs->state = vs_initial_handshake_server_send;

	vs->depth = 32;

	ts->p = vs;

	dolog("VNC: new session with %s\n", vs->client_addr.c_str());

	// yes, this if is strictly seen not required
	if (vs->state == vs_initial_handshake_server_send) {
		const char initial_message[] = "RFB 003.008\n";

		dolog("VNC: send handshake of 12 bytes\n");
		ts->t->send_data(ts, (const uint8_t *)initial_message, 12, true);  // must be 12 bytes

		vs->state = vs_initial_handshake_client_resp;
	}

	vs->th = new std::thread(vnc_thread, ts);

	return true;
}

bool vnc_new_data(tcp_session_t *ts, const packet *pkt, const uint8_t *data, size_t data_len, void *private_data)
{
	vnc_session_data *vs = dynamic_cast<vnc_session_data *>(ts->p);

	if (!vs) {
		dolog("VNC: Data for a non-existing session\n");
		return false;
	}

	vnc_thread_work_t *work = new vnc_thread_work_t;
	work->pkt = pkt->duplicate();
	work->data = (char *)duplicate((const uint8_t *)data, data_len);
	work->data_len = data_len;

	const std::lock_guard<std::mutex> lck(vs->w_lock);
	vs->wq.push(work);
	vs->w_cond.notify_one();

	return true;
}

void vnc_thread(void *ts_in)
{
	tcp_session_t *ts = (tcp_session_t *)ts_in;
	vnc_session_data *vs = dynamic_cast<vnc_session_data *>(ts->p);
	bool rc = true;

	set_thread_name("vnc");

	std::vector<int32_t> encodings;
	int n_encodings = -1;

	int running_cmd = -1, ignore_data_n = -1;

	for(;vs->state != vs_terminate;) {
		vnc_thread_work_t *work = nullptr;

		{
			std::unique_lock<std::mutex> lck(vs->w_lock);

			for(;;) {
				if (vs->wq.empty() == false) {
					work = vs->wq.front();
					vs->wq.pop();
					break;
				}

				vs->w_cond.wait(lck);
			}
		}

		if (!work) {
			dolog("VNC: %zu TERMINATE THREAD REQUESTED\n", get_us());
			break;
		}

		if (!work->pkt) {  // means "update"
			uint8_t *message = nullptr;
			size_t message_len = 0;

			calculate_fb_update(&fb, encodings, true, 0, 0, fb.w, fb.h, vs->depth, &message, &message_len);

			dolog("VNC: %zu will update for %s, output is %zu bytes\n", get_us(), vs->client_addr.c_str(), message_len);
			ts->t->send_data(ts, message, message_len, false);

			free(message);
		}

		vs->buffer = (char *)realloc(vs->buffer, vs->buffer_size + work->data_len);

		memcpy(&vs->buffer[vs->buffer_size], work->data, work->data_len);
		vs->buffer_size += work->data_len;

		dolog("VNC: state: %d\n", vs->state);
	
		if (vs->state == vs_initial_handshake_client_resp) {
			char *handshake = (char *)get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 12);

			if (handshake) {
				std::string handshake_str = std::string(handshake, 12);

				if (memcmp(handshake, "RFB", 3) == 0) {  // let's not be too picky
					dolog("VNC: Client responded with protocol version: %s\n", handshake_str.c_str());
					vs->state = vs_security_handshake_server;
				}
				else {
					rc = false;
					dolog("VNC: Unexpected/invalid protocol version: %s\n", handshake_str.c_str());
				}

				free(handshake);
			}
		}

		if (vs->state == vs_security_handshake_server) {
			uint8_t message[] = { 1,  // number of security types
				1,  // 'None'
			};

			dolog("VNC: ack security types, %zu bytes\n", sizeof message);
			ts->t->send_data(ts, message, sizeof message, false);

			vs->state = vs_security_handshake_client_resp;
		}

		if (vs->state == vs_security_handshake_client_resp) {
			uint8_t *chosen_sec = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 1);

			if (chosen_sec) {
				if (*chosen_sec == 1) {  // must have chosen security type 'None'
					uint8_t response[] = { 0, 0, 0, 0 };  // OK
					dolog("VNC: Valid security type chosen, %zu bytes\n", sizeof response);
					ts->t->send_data(ts, response, sizeof response, false);

					vs->state = vs_client_init;
				}
				else {
					rc = false;

					uint8_t response[] = { 0, 0, 0, 1 };  // failed
					dolog("VNC: Unexpected/invalid security type: %d (%zu bytes)\n", *chosen_sec, sizeof response);
					ts->t->send_data(ts, response, sizeof response, false);
				}

				free(chosen_sec);
			}
		}

		if (vs->state == vs_client_init) {
			uint8_t *client_init = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 1);

			if (client_init) {
				dolog("VNC: client asks for %sdesktop sharing\n", *client_init ? "" : "NO ");

				vs->state = vs_server_init;

				free(client_init);
			}
		}

		if (vs->state == vs_server_init) {  // 7.3.2
			uint8_t message[] = {
				uint8_t(fb.w >> 8), uint8_t(fb.w & 255),
				uint8_t(fb.h >> 8), uint8_t(fb.h & 255),
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

			dolog("VNC: server init, %zu bytes\n", sizeof message);
			ts->t->send_data(ts, message, sizeof message, false);

			vs->state = vs_running_waiting_cmd;
		}

		if (vs->state == vs_running_waiting_cmd) {
			uint8_t *cmd = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 1);

			if (cmd) {
				running_cmd = *cmd;

				dolog("VNC: Received command %d\n", running_cmd);

				vs->state = vs_running_waiting_data;

				free(cmd);
			}
		}

		if (vs->state == vs_running_waiting_data) {
			bool proceed = false;
			int ignore_n = 0;

			dolog("VNC: waiting for data for command %d\n", running_cmd);

			if (running_cmd == 0) {  // SetPixelFormat, 7.5.1
				dolog("VNC: Retrieving pixelformat\n");

				uint8_t *pf = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 19);

				if (pf) {
					const uint8_t *data = &pf[3];  // skip padding

					vs->depth = data[1];

					uint16_t rmax = (data[4] << 8) | data[5];
					uint16_t gmax = (data[6] << 8) | data[7];
					uint16_t bmax = (data[8] << 8) | data[9];

					dolog("VNC: Changed 'depth'(BPP) to %d (bpp: %d, red/green/blue max: %d/%d/%d)\n", vs->depth, data[0], rmax, gmax, bmax);

					vs->state = vs_running_waiting_cmd;

					free(pf);
				}
			}
			else if (running_cmd == 1) {  // ??? FIXME
				dolog("VNC: STRANGE COMMAND\n");
				// assume it is a keep-alive or so
				vs->state = vs_running_waiting_cmd;
			}
			else if (running_cmd == 2) {  // SetEncodings, 7.5.2
				uint8_t *parameters = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 3);

				if (parameters) {
					n_encodings = (parameters[1] << 8) | parameters[2];
					dolog("VNC: Retrieving number of encodings (%d)\n", n_encodings);

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

					calculate_fb_update(&fb, encodings, incremental, x, y, w, h, vs->depth, &message, &message_len);

					dolog("VNC: framebuffer update %zu bytes for %dx%d at %d,%d: %zu bytes\n", message_len, w, h, x, y, message_len);

					ts->t->send_data(ts, message, message_len, false);

					free(message);

					free(parameters);

					proceed = true;
				}
			}
			else if (running_cmd == 4) {  // KeyEvent
				ignore_n = 7;
				dolog("VNC: CLIENT KeyEvent (ignore %d)\n", ignore_n);
			}
			else if (running_cmd == 5) {  // PointerEvent
				ignore_n = 5;
				dolog("VNC: CLIENT PointerEvent (ignore %d)\n", ignore_n);
			}
			else if (running_cmd == 6) {  // ClientCutText
				uint8_t *parameters = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 7);

				if (parameters) {
					ignore_data_n = (parameters[3] << 24) | (parameters[4] << 16) | (parameters[5] << 8) | parameters[6];
					dolog("VNC: ClientCutText (ignore %d)\n", ignore_data_n);

					vs->state = vs_running_waiting_data_ignore;

					free(parameters);
				}
			}
			else {
				dolog("VNC: Command %d not known (data state)\n", running_cmd);
				rc = false;
			}

			// part of the command
			if (ignore_n) {
				dolog("VNC: Ignore %d bytes from command\n", ignore_n);

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
			dolog("VNC: Ignore %d command parameters\n", ignore_data_n);

			uint8_t *ignore = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, ignore_data_n);

			if (ignore) {
				vs->state = vs_running_waiting_cmd;

				ignore_data_n = -1;

				free(ignore);
			}
		}

		if (vs->state == vs_running_waiting_data_extra) {
			if (running_cmd == 2) {  // SetEncodings
				dolog("VNC: Retrieving %d encodings\n", n_encodings);

				uint8_t *encodings_bin = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, n_encodings * 4);

				if (encodings_bin) {
					encodings.clear();

					for(int i=0; i<n_encodings; i++) {
						int o = i * 4;
						encodings.push_back((encodings_bin[o + 0] << 24) | (encodings_bin[o + 1] << 16) | (encodings_bin[o + 2] << 8) | encodings_bin[o + 3]);
					}

					n_encodings = -1;

					vs->state = vs_running_waiting_cmd;

					free(encodings_bin);
				}
			}
			else {
				dolog("VNC: Command %d not known (data-extra state)\n", running_cmd);
				rc = false;
			}
		}

		if (!rc)
			vs->state = vs_terminate;

		delete work->pkt;
		delete [] work->data;
		delete work;
	}

	dolog("VNC: Thread terminating for %s\n", vs->client_addr.c_str());
}

void vnc_close_session(tcp_session_t *ts, private_data *pd)
{
	if (ts -> p) {
		vnc_session_data *vs = dynamic_cast<vnc_session_data *>(ts->p);

		{
			const std::lock_guard<std::mutex> lck(vs->w_lock);
			vs->wq.push(nullptr);
			vs->w_cond.notify_one();
		}

		vs->th->join();
		delete vs->th;

		free(vs->buffer);

		delete vs;

		ts->p = nullptr;
	}
}

tcp_port_handler_t vnc_get_handler()
{
	tcp_port_handler_t tcp_vnc;

	tcp_vnc.init = vnc_init;
	tcp_vnc.new_session = vnc_new_session;
	tcp_vnc.new_data = vnc_new_data;
	tcp_vnc.session_closed = vnc_close_session;
	tcp_vnc.pd = nullptr;

	return tcp_vnc;
}
