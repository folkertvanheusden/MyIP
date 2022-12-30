// (C) 2022-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <algorithm>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "log.h"
#include "phys_ppp.h"
#include "packet.h"
#include "str.h"
#include "utils.h"


phys_ppp::phys_ppp(const size_t dev_index, stats *const s, const std::string & dev_name, const int bps, const any_addr & my_mac, const bool emulate_modem_xp, const any_addr & opponent_address) :
	phys_gen_ppp(dev_index, s, dev_name, my_mac, opponent_address),
	emulate_modem_xp(emulate_modem_xp)
{
}

phys_ppp::~phys_ppp()
{
}

bool phys_ppp::transmit_low(const std::vector<uint8_t> & payload, const uint16_t protocol, const std::vector<uint8_t> & ACCM, const bool not_ppp_meta)
{
	bool ok = true;

        std::vector<uint8_t> out_wrapped = wrap_in_ppp_frame(payload, protocol, ACCM, not_ppp_meta);

	send_lock.lock();
	int rc = WRITE(fd, out_wrapped.data(), out_wrapped.size());
	send_lock.unlock();

	if (size_t(rc) != out_wrapped.size()) {
		DOLOG(ll_error, "phys_ppp: problem sending packet (%d for %zu bytes)\n", rc, out_wrapped.size());

		if (rc == -1)
			DOLOG(ll_error, "phys_ppp: %s\n", strerror(errno));

		ok = false;
	}

	return ok;
}

void phys_ppp::operator()()
{
	DOLOG(ll_debug, "phys_ppp: thread started\n");

	set_thread_name("myip-phys_ppp");

	std::vector<uint8_t> packet_buffer;

	std::string modem;
	bool modem_7e_flag = false;

	struct pollfd fds[] = { { fd, POLLIN, 0 } };

	while(!stop_flag) {
		int rc = poll(fds, 1, 150);
		if (rc == -1) {
			if (errno == EINTR)
				continue;

			DOLOG(ll_error, "poll: %s", strerror(errno));
			exit(1);
		}

		if (rc == 0)
			continue;

		uint8_t buffer = 0x00;
		int size = read(fd, (char *)&buffer, 1);
		if (size == -1)
			continue;

		if (buffer == 0x7e) {
			if (packet_buffer.empty() == false) {  // START/END of packet
				auto unwrapped = unwrap_ppp_frame(packet_buffer, ACCM_rx);

				stats_add_counter(phys_ifInOctets,   unwrapped.size());
				stats_add_counter(phys_ifHCInOctets, unwrapped.size());
				stats_inc_counter(phys_ifInUcastPkts);

				process_incoming_packet(unwrapped);

				packet_buffer.clear();

				modem_7e_flag = false;
				modem.clear();
			}
		}
		else {
			packet_buffer.push_back(buffer);

			if (buffer == 0x7e)
				modem_7e_flag = true;

			if (emulate_modem_xp && modem_7e_flag == false) {
				if ((buffer >= 32 && buffer < 127) || buffer == 10 || buffer == 13) {
					modem += (char)buffer;

					if (modem.find("ATDT") != std::string::npos) {
						DOLOG(ll_debug, "ATDT -> CONNECT (%s)\n", modem.c_str());
						write(fd, "CONNECT\r\n", 9);
						modem.clear();
					}
					else if (modem.find("AT") != std::string::npos) {
						DOLOG(ll_debug, "AT -> OK (%s)\n", modem.c_str());
						write(fd, "OK\r\n", 4);
						modem.clear();
					}
					else if (modem.find("CLIENT") != std::string::npos) {
						// Windows XP direction PPP connection
						DOLOG(ll_debug, "CLIENT -> SERVER\n");
						write(fd, "SERVER\r\n", 7);
						modem.clear();
					}
				}
			}
		}
	}

	DOLOG(ll_info, "phys_ppp: thread stopped\n");
}
