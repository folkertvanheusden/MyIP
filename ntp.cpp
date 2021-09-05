// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "ntp.h"
#include "udp.h"
#include "utils.h"

#define NTP_EPOCH (86400U * (365U * 70U + 17U))

struct sntp_datagram
{
        unsigned char mode : 3;
        unsigned char vn : 3;
        unsigned char li : 2;
        /* data */
        unsigned char stratum;
        char poll;
        char precision;
        u_int32_t root_delay;
        u_int32_t root_dispersion;
        u_int32_t reference_identifier;
        u_int32_t reference_timestamp_secs;
        u_int32_t reference_timestamp_fraq;
        u_int32_t originate_timestamp_secs;
        u_int32_t originate_timestamp_fraq;
        u_int32_t receive_timestamp_seqs;
        u_int32_t receive_timestamp_fraq;
        u_int32_t transmit_timestamp_secs;
        u_int32_t transmit_timestamp_fraq;
};

ntp::ntp(stats *const s, udp *const u, const any_addr & my_ip, const any_addr & upstream_ntp_server, const bool broadcast) : u(u), my_ip(my_ip), upstream_ntp_server(upstream_ntp_server), broadcast(broadcast)
{
	ntp_requests = s->register_stat("ntp_requests");
	ntp_invalid  = s->register_stat("ntp_invalid");
	ntp_time_req = s->register_stat("ntp_time_req");

	for(int i=0; i<8; i++) {
		char name[] = "ntp_t_req_v_";
		name[11] = '0' + i;

		ntp_t_req_v[i] = s->register_stat(name);
	}

	ntp_broadcast = s->register_stat("ntp_broadcast");

	th = new std::thread(std::ref(*this));
}

ntp::~ntp()
{
	stop_flag = true;
	th->join();
	delete th;
}

void ntp::input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, void *const pd)
{
	stats_inc_counter(ntp_requests);

	sntp_datagram *sntp = reinterpret_cast<sntp_datagram *>(p->get_data());

	if (sntp->mode == 1 || sntp->mode == 3) { // time request
		stats_inc_counter(ntp_time_req);

		stats_inc_counter(ntp_t_req_v[sntp->vn]);

		sntp_datagram msgout { 0 };

		msgout.li = 0;
		msgout.mode = sntp->mode == 1 ? 1 : 4; // 4: server
		msgout.vn = 3;
		msgout.precision = -18; // 3.8us
		msgout.stratum = 2;
		msgout.root_delay = 369098752; // not known
		msgout.root_dispersion = 369098752; // not known
		msgout.poll = 16;

		// what to do with IPv6 addresses?
		upstream_ntp_server.get((uint8_t *)&msgout.reference_identifier, 4);

		msgout.originate_timestamp_secs = sntp->transmit_timestamp_secs;
		msgout.originate_timestamp_fraq = sntp->transmit_timestamp_fraq;

		struct timespec recv_now = p->get_recv_ts();

                msgout.receive_timestamp_seqs = htonl(recv_now.tv_sec + NTP_EPOCH);
                msgout.receive_timestamp_fraq = htonl(recv_now.tv_nsec / 1000 * 4295);

		struct timespec now { 0, 0 };
		if (clock_getres(CLOCK_REALTIME, &now) == -1)
			dolog(warning, "clock_getres failed: %s", strerror(errno));

                msgout.reference_timestamp_secs = htonl(now.tv_sec + NTP_EPOCH);
                msgout.reference_timestamp_fraq = htonl(now.tv_nsec / 1000 * 4295);

                msgout.transmit_timestamp_secs = htonl(now.tv_sec + NTP_EPOCH);
                msgout.transmit_timestamp_fraq = htonl(now.tv_nsec / 1000 * 4295);

		u->transmit_packet(src_ip, src_port, dst_ip, dst_port, (const uint8_t *)&msgout, sizeof msgout);

		dolog(debug, "NTP: packet transmitted\n");
	}
}

void ntp::operator()()
{
	uint64_t prev = 0;

	set_thread_name("myip-ntp");

	while(!stop_flag) {
		uint64_t now = get_us();
		uint64_t diff = now - prev;

		// send a packet each 64s
		if (diff < 64000000) {
			if (diff > 100000)
				diff = 100000;

			myusleep(diff);
			
			continue;
		}

		prev = now;

		dolog(debug, "NTP: Sending broadcast\n");

		stats_inc_counter(ntp_broadcast);

		sntp_datagram msgout { 0 };

		msgout.li = 0;
		msgout.mode = 5; // broadcast
		msgout.vn = 3;
		msgout.precision = -18; // 3.8us
		msgout.stratum = 2;
		msgout.root_delay = 1; // not known
		msgout.root_dispersion = 1; // not known
		msgout.poll = 16;

		// what to do with IPv6 addresses?
		upstream_ntp_server.get((uint8_t *)&msgout.reference_identifier, 4);

		msgout.originate_timestamp_secs = 0;
		msgout.originate_timestamp_fraq = 0;
                msgout.receive_timestamp_seqs = 0;
                msgout.receive_timestamp_fraq = 0;

		struct timeval nowtv;
		gettimeofday(&nowtv, nullptr);

                msgout.reference_timestamp_secs = htonl(nowtv.tv_sec + NTP_EPOCH);
                msgout.reference_timestamp_fraq = htonl(nowtv.tv_usec * 4295);

                msgout.transmit_timestamp_secs = htonl(nowtv.tv_sec + NTP_EPOCH);
                msgout.transmit_timestamp_fraq = htonl(nowtv.tv_usec * 4295);

		constexpr uint8_t ip_tgt[] = { 224, 0, 1, 1 };

		u->transmit_packet(any_addr(ip_tgt, 4), 123, my_ip, 123, (const uint8_t *)&msgout, sizeof msgout);
	}
}
