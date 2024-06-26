// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "log.h"
#include "ntp.h"
#include "str.h"
#include "time.h"
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
	// 1.3.6.1.4.1.57850.1.4: ntp
	ntp_requests  = s->register_stat("ntp_requests",  "1.3.6.1.4.1.57850.1.4.1");
	ntp_invalid   = s->register_stat("ntp_invalid",   "1.3.6.1.4.1.57850.1.4.2");
	ntp_time_req  = s->register_stat("ntp_time_req",  "1.3.6.1.4.1.57850.1.4.3");
	ntp_broadcast = s->register_stat("ntp_broadcast", "1.3.6.1.4.1.57850.1.4.4");

	for(int i=0; i<8; i++) {
		char stat_name[] = "ntp_t_req_v_";

		stat_name[11] = '0' + i;

		std::string snmp_name = myformat("1.3.6.1.4.1.57850.1.4.5.%d", i + 1);

		ntp_t_req_v[i] = s->register_stat(stat_name, snmp_name);
	}

	if (broadcast)
		th = new std::thread(std::ref(*this));
}

ntp::~ntp()
{
	stop_flag.signal_stop();

	if (th) {
		th->join();
		delete th;
	}
}

void ntp::input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, session_data *const pd)
{
	if (dst_ip != my_ip)
		return;

	stats_inc_counter(ntp_requests);

	if (p->get_size() < sizeof(sntp_datagram *)) {
		stats_inc_counter(ntp_invalid);

		return;
	}

	sntp_datagram *sntp = reinterpret_cast<sntp_datagram *>(p->get_data());

	if (sntp->mode == 3) { // time request
		stats_inc_counter(ntp_time_req);

		stats_inc_counter(ntp_t_req_v[sntp->vn]);

		sntp_datagram msgout { 0 };

		msgout.li = 0;
		msgout.mode = 4; // 4: server
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
		if (clock_gettime(CLOCK_REALTIME, &now) == -1)
			DOLOG(ll_warning, "clock_gettime failed: %s", strerror(errno));

                msgout.reference_timestamp_secs = htonl(now.tv_sec + NTP_EPOCH);
                msgout.reference_timestamp_fraq = htonl(now.tv_nsec / 1000 * 4295);

                msgout.transmit_timestamp_secs = htonl(now.tv_sec + NTP_EPOCH);
                msgout.transmit_timestamp_fraq = htonl(now.tv_nsec / 1000 * 4295);

		u->transmit_packet(src_ip, src_port, dst_ip, dst_port, (const uint8_t *)&msgout, sizeof msgout);

		DOLOG(ll_debug, "NTP: packet transmitted\n");
	}
}

void ntp::operator()()
{
	set_thread_name("myip-ntp");

	uint64_t prev = 0;

	for(;;) {
		// send a packet each 64s
		if (stop_flag.sleep(64000))
			break;

		uint64_t now = get_us();

		DOLOG(ll_debug, "NTP: Sending broadcast\n");

		stats_inc_counter(ntp_broadcast);

		sntp_datagram msgout { 0 };

		msgout.li              = 0;
		msgout.mode            = 5; // broadcast
		msgout.vn              = 3;
		msgout.precision       = -18; // 3.8us
		msgout.stratum         = 2;
		msgout.root_delay      = 1; // not known
		msgout.root_dispersion = 1; // not known
		msgout.poll            = 16;

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

		u->transmit_packet(any_addr(any_addr::ipv4, ip_tgt), 123, my_ip, 123, (const uint8_t *)&msgout, sizeof msgout);
	}
}
