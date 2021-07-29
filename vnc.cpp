// (C) 2021 by folkert van heusden <mail@vanheusden.com>, released under AGPL v3.0
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

typedef enum {  vs_initial_handshake_server_send = 0,
		vs_initial_handshake_client_resp,
		vs_security_handshake_server,
		vs_security_handshake_client_resp,
		vs_client_init,
		vs_server_init,
		vs_running_waiting_cmd,
		vs_running_waiting_data,
		vs_running_waiting_data_extra,
		vs_running_waiting_data_ignore,
		vs_terminate
} vnc_state_t;

typedef struct {
	// nullptr if update requested
	packet *pkt;

	char *data;
	size_t data_len;
} vnc_thread_work_t;

typedef struct {
	std::string client_addr;

	char *buffer;
	size_t buffer_size;

	vnc_state_t state;

	std::thread *th;

	std::queue<vnc_thread_work_t *> wq;
        std::condition_variable w_cond;
        mutable std::mutex w_lock;
} vnc_session_t;

struct frame_buffer_t
{
	std::thread *th;

	int w, h;

	uint8_t *buffer;

        mutable std::mutex cb_lock;
	std::set<vnc_session_t *> callbacks;

	void register_callback(vnc_session_t *p) {
		const std::lock_guard<std::mutex> lck(cb_lock);

		auto rc = callbacks.insert(p);
		assert(rc.second);
	}

	void unregister_callback(vnc_session_t *p) {
		const std::lock_guard<std::mutex> lck(cb_lock);

		// may have not been registered if the connection
		// is dropped before then handshake was fully
		// performed
		callbacks.erase(p);
	}

	void callback() {
		const std::lock_guard<std::mutex> lck(cb_lock);

		for(auto vs : callbacks) {
			const std::lock_guard<std::mutex> lck(vs->w_lock);

		dolog("%zu CALLBACK for %s\n", get_us(), vs->client_addr.c_str());

			vs->wq.push(new vnc_thread_work_t());

			vs->w_cond.notify_one();
		}
	}
} fb;

void vnc_thread(void *ts_in);

void frame_buffer_thread(void *ts_in);

void vnc_init()
{
	fb.w = 128; // FIXME 640x480
	fb.h = 64;

	size_t n_bytes = fb.w * fb.h * 3;
	fb.buffer = new uint8_t[n_bytes];
	memset(fb.buffer, 0x00, n_bytes);

	fb.th = new std::thread(frame_buffer_thread, &fb);
}

void draw_text(frame_buffer_t *fb, int x, int y, const char *text)
{
	int len = strlen(text);

	for(int i=0; i<len; i++) {
		for(int cy=0; cy<8; cy++) {
			for(int cx=0; cx<8; cx++) {
				int o = (cy + y) * fb -> w * 3 + (x + i * 8 + cx) * 3;

				int c = text[i] & 127;
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

	frame_buffer_t *fb = (frame_buffer_t *)fb_in;

	int x = fb->w / 2, y = fb->h / 2;
	int dx = 1, dy = 1;

	uint64_t latest_update = 0;

	for(;;) {  // FIXME terminate if requested
		// increase green
		assert(x < fb->w);
		assert(y < fb->h);
		fb->buffer[y * fb->w * 3 + x * 3 + 1]++;

		x += dx;
		y += dy;

		if (x >= fb->w) {
			x = fb->w - 1;
			dx = -((rand() % 3) + 1);
		}

		if (y >= fb->h) {
			y = fb->h - 1;
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
		int cx = rand() % fb -> w;
		int cy = rand() % fb -> h;
		fb->buffer[cy * fb->w * 3 + cx * 3 + 0]++;

		uint64_t now = get_us();

		if (now - latest_update >= 1000000) {  // 1 time per second
			dolog("%zu FB UPDATE\n", now);
			latest_update = now;

			time_t now = time(nullptr);
			struct tm *tm = gmtime(&now);

			char *text = nullptr;
			asprintf(&text, "%02d:%02d:%02d - MyIP", tm->tm_hour, tm->tm_min, tm->tm_sec);

			draw_text(fb, fb->w / 2 - 15 * 8 / 4, fb->h / 2 - 8 / 2, text);

			free(text);

			fb->callback();
		}

		usleep(1000);  // ignore any errors during usleep
	}

	delete [] fb->buffer;
}

void calculate_fb_update(frame_buffer_t *fb, std::vector<int32_t> & encodings, bool incremental, int x, int y, int w, int h, uint8_t **message, size_t *message_len)
{
	*message_len =  4 +  // FramebufferUpdate header
			12 +  // for each block of pixels
			w * h * 4;  // RGBA pixels

	*message = (uint8_t *)malloc(*message_len);

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
	for(int yo=y; yo<y + h; yo++) {
		for(int xo=x; xo<x + w; xo++) {
			(*message)[o++] = fb->buffer[yo * w * 3 + xo * 3 + 2];  // blue
			(*message)[o++] = fb->buffer[yo * w * 3 + xo * 3 + 1];  // green
			(*message)[o++] = fb->buffer[yo * w * 3 + xo * 3 + 0];  // red
			(*message)[o++] = 255;  // alpha
		}
	}
}

bool vnc_new_session(tcp_session_t *ts, const packet *pkt, void *private_data)
{
	vnc_session_t *vs = new vnc_session_t();

	std::pair<const uint8_t *, int> src_addr = pkt->get_src_addr();
	vs->client_addr = ip_to_str(src_addr);

	vs->buffer = nullptr;
	vs->buffer_size = 0;

	vs->state = vs_initial_handshake_server_send;

	ts->p = vs;

	dolog("VNC: new session with %s\n", vs->client_addr.c_str());

	// yes, this if is strictly seen not required
	if (vs->state == vs_initial_handshake_server_send) {
		const char initial_message[] = "RFB 003.008\n";

		ts->t->send_data(ts, (const uint8_t *)initial_message, 12, true);  // must be 12 bytes

		vs->state = vs_initial_handshake_client_resp;
	}

	vs->th = new std::thread(vnc_thread, ts);

	return true;
}

bool vnc_new_data(tcp_session_t *ts, const packet *pkt, const uint8_t *data, size_t data_len, void *private_data)
{
	vnc_session_t *vs = (vnc_session_t *)ts->p;

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
	vnc_session_t *vs = (vnc_session_t *)ts->p;
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
					dolog("%zu have data %p %p\n", get_us(), work, work?work->pkt:nullptr);
					break;
				}

				vs->w_cond.wait(lck);
			}
		}

		if (!work) {
			dolog("%zu TERMINATE THREAD REQUESTED\n", get_us());
			break;
		}

		if (!work->pkt) {  // means "update"
			dolog("%zu will update for %s\n", get_us(), vs->client_addr.c_str());
			uint8_t *message = nullptr;
			size_t message_len = 0;

			calculate_fb_update(&fb, encodings, true, 0, 0, fb.w, fb.h, &message, &message_len);

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

			ts->t->send_data(ts, message, sizeof message, false);

			vs->state = vs_security_handshake_client_resp;
		}

		if (vs->state == vs_security_handshake_client_resp) {
			uint8_t *chosen_sec = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 1);

			if (chosen_sec) {
				if (*chosen_sec == 1) {  // must have chosen security type 'None'
					dolog("VNC: Valid security type chosen\n");

					uint8_t response[] = { 0, 0, 0, 0 };  // OK
					ts->t->send_data(ts, response, sizeof response, false);

					vs->state = vs_client_init;
				}
				else {
					rc = false;
					dolog("VNC: Unexpected/invalid security type: %d\n", *chosen_sec);

					uint8_t response[] = { 0, 0, 0, 1 };  // failed
					ts->t->send_data(ts, response, sizeof response, false);
				}

				free(chosen_sec);
			}
		}

		if (vs->state == vs_client_init) {
			uint8_t *client_init = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 1);

			if (client_init) {
				if (*client_init)
					dolog("VNC: client asks for desktop sharing\n");

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

			ts->t->send_data(ts, message, sizeof message, false);

			fb.register_callback(vs);

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

			if (running_cmd == 0)  // SetPixelFormat, 7.5.1
				ignore_n = 19;
			else if (running_cmd == 2) {  // SetEncodings, 7.5.2
				uint8_t *parameters = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 3);

				if (parameters) {
					n_encodings = (parameters[1] << 8) | parameters[2];

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

					calculate_fb_update(&fb, encodings, incremental, x, y, w, h, &message, &message_len);

					dolog("SEND %zu bytes for %dx%d at %d,%d\n", message_len, w, h, x, y);

					ts->t->send_data(ts, message, message_len, false);

					free(message);

					free(parameters);

					proceed = true;
				}
			}
			else if (running_cmd == 4) {  // KeyEvent
				dolog("CLIENT KeyEvent\n");
				ignore_n = 7;
			}
			else if (running_cmd == 5) {  // PointerEvent
				dolog("CLIENT PointerEvent\n");
				ignore_n = 5;
			}
			else if (running_cmd == 6) {  // ClientCutText
				uint8_t *parameters = get_from_buffer((uint8_t **)&vs->buffer, &vs->buffer_size, 7);

				if (parameters) {
					ignore_data_n = (parameters[3] << 24) | (parameters[4] << 16) | (parameters[5] << 8) | parameters[6];

					vs->state = vs_running_waiting_data_ignore;

					free(parameters);
				}
			}
			else {
				dolog("VNC: Command %d not known (data state)\n", running_cmd);
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

	fb.unregister_callback(vs);

	dolog("VNC: Thread terminating for %s\n", vs->client_addr.c_str());
}

void vnc_close_session(tcp_session_t *ts, void *private_data)
{
	if (ts -> p) {
		vnc_session_t *vs = (vnc_session_t *)ts->p;

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
	tcp_vnc.private_data = nullptr;

	return tcp_vnc;
}
