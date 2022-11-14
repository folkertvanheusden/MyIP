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
	phys_slip(dev_index, s, dev_name, bps, my_mac),
	emulate_modem_xp(emulate_modem_xp),
	opponent_address(opponent_address)
{
	ACCM_rx.resize(32);
	ACCM_rx.at(0) = 0xff;
	ACCM_rx.at(1) = 0xff;
	ACCM_rx.at(2) = 0xff;
	ACCM_rx.at(3) = 0xff;

	ACCM_tx = ACCM_rx;  // initially only

	// from
	// https://stackoverflow.com/questions/45198049/calculating-the-ppp-frame-check-sequence
	constexpr uint16_t polynomial = 0x8408;

	for(int i = 0; i < 256; i++) {
            uint16_t value = 0;
            uint8_t temp = i;

            for(int j = 0; j < 8; j++) {
                if ((value ^ temp) & 0x0001)
                    value = uint16_t((value >> 1) ^ polynomial);
                else
                    value >>= 1;

                temp >>= 1;
            }

            fcstab[i] = value;
        }
}

phys_ppp::~phys_ppp()
{
}

void phys_ppp::start()
{
	th = new std::thread(std::ref(*this));
}

std::vector<uint8_t> phys_ppp::wrap_in_ppp_frame(const std::vector<uint8_t> & payload, const uint16_t protocol, const std::vector<uint8_t> & ACCM, const bool not_ppp_meta)
{
	std::vector<uint8_t> temp;

	if (!ac_field_compression || !not_ppp_meta) {
		temp.push_back(0xff);  // standard broadcast address
		temp.push_back(0x03);  // unnumbered data
	}

	if (protocol_compression && protocol < 0x0100 && not_ppp_meta)
		temp.push_back(protocol);
	else {
		temp.push_back(protocol >> 8);
		temp.push_back(protocol);
	}

	std::copy(payload.begin(), payload.end(), std::back_inserter(temp));	
	// TODO? padding?

	std::vector<uint8_t> out;
	out.push_back(0x7e);  // flag

	uint16_t fcs = 0xFFFF;

	for(int i = 0; i < temp.size(); i++)
		fcs = (fcs >> 8) ^ fcstab[(fcs ^ temp.at(i)) & 0xff];

	fcs ^= 0xFFFF;

	temp.push_back(fcs);
	temp.push_back(fcs >> 8);

	for(size_t i=0; i<temp.size(); i++) {
		uint8_t b = temp.at(i);

		if (b == 0x7d || b == 0x7e || (ACCM.at(b >> 3) & (1 << (b & 7))) || (b < 0x20 && !not_ppp_meta)) {
			out.push_back(0x7d);
			out.push_back(b ^ 0x20);
		}
		else {
			out.push_back(b);
		}
	}

	out.push_back(0x7e);  // flag

	return out;
}

std::vector<uint8_t> unwrap_ppp_frame(const std::vector<uint8_t> & payload, const std::vector<uint8_t> & ACCM)
{
	std::vector<uint8_t> out;

	std::string d;
	for(size_t i=0; i<payload.size(); i++)
		d += myformat("%02x ", payload.at(i));
	DOLOG(debug, "ppp pkt before: %s\n", d.c_str());

	for(size_t i=0; i<payload.size();) {
		uint8_t c = payload.at(i++);

		if (c == 0x7d)
			out.push_back(payload.at(i++) ^ 0x20);
		else
			out.push_back(c);
	}

	d.clear();
	for(size_t i=0; i<out.size(); i++)
		d += myformat("%02x ", out.at(i));
	DOLOG(debug, "ppp pkt after: %s\n", d.c_str());

	return out;
}

void phys_ppp::send_Xcp(const uint8_t code, const uint8_t identifier, const uint16_t protocol, const std::vector<uint8_t> & data)
{
	DOLOG(debug, "ppp send code %d\n", code);

	std::vector<uint8_t> out;

	out.push_back(code);
	out.push_back(identifier);

	size_t len_offset = out.size();
	out.push_back(0);  // placeholder for length (MSB)
	out.push_back(0);  // placeholder for length (LSB)

	std::copy(data.begin(), data.end(), std::back_inserter(out));

	out.at(len_offset) = out.size() >> 8;
	out.at(len_offset + 1) = out.size() & 255;

	std::vector<uint8_t> out_wrapped = wrap_in_ppp_frame(out, protocol, ACCM_tx, false);

	send_lock.lock();
	if (write(fd, out_wrapped.data(), out_wrapped.size()) != out_wrapped.size())
		DOLOG(ll_error, "write error\n");
	send_lock.unlock();
}

void phys_ppp::send_rej(const uint16_t protocol, const uint8_t identifier, const std::vector<uint8_t> & options)
{
	DOLOG(debug, "ppp send rej for protocol %04x, identifier %02x\n", protocol, identifier);

	send_Xcp(4, identifier, protocol, options);
}

void phys_ppp::send_ack(const uint16_t protocol, const uint8_t identifier, const std::vector<uint8_t> & options)
{
	DOLOG(debug, "ppp send ack for protocol %04x, identifier %02x\n", protocol, identifier);

	send_Xcp(2, identifier, protocol, options);
}

void phys_ppp::send_nak(const uint16_t protocol, const uint8_t identifier, const std::vector<uint8_t> & options)
{
	DOLOG(debug, "ppp send nak for protocol %04x, identifier %02x\n", protocol, identifier);

	send_Xcp(3, identifier, protocol, options);
}

bool phys_ppp::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size)
{
	std::vector temp(payload, &payload[pl_size]);
	std::vector<uint8_t> ppp_frame = wrap_in_ppp_frame(temp, 0x0021 /* IP */, ACCM_tx, true);

	stats_add_counter(phys_ifOutOctets, ppp_frame.size());
	stats_add_counter(phys_ifHCOutOctets, ppp_frame.size());
	stats_inc_counter(phys_ifOutUcastPkts);

	bool ok = true;

	send_lock.lock();
	int rc = write(fd, ppp_frame.data(), ppp_frame.size());
	send_lock.unlock();

	if (size_t(rc) != ppp_frame.size()) {
		DOLOG(ll_error, "phys_ppp: problem sending packet (%d for %zu bytes)\n", rc, ppp_frame.size());

		if (rc == -1)
			DOLOG(ll_error, "phys_ppp: %s\n", strerror(errno));

		ok = false;
	}

	return ok;
}

void phys_ppp::handle_ccp(const std::vector<uint8_t> & data)
{
	size_t ccp_offset = 4;

	const uint8_t code = data.at(ccp_offset + 0);
	const uint8_t identifier = data.at(ccp_offset + 1);

	uint16_t length = (data.at(ccp_offset + 2) << 8) | data.at(ccp_offset + 3);
	DOLOG(debug, "CCP code %02x identifier %02x length %d\n", code, identifier, length);

	if (data.size() < 4 + length) {
		DOLOG(debug, "\tINVALID SIZE %zu < %d\n", data.size(), 4 + 8 + length);
		return;
	}

	if (code == 0x01) {  // options
		std::vector<uint8_t> ack, rej;

		DOLOG(debug, "\tOPTIONS:\n");

		size_t options_offset = ccp_offset + 4;

		while(options_offset < data.size() - 2) {
			size_t next_offset = options_offset;
			uint8_t type = data.at(options_offset++);
			uint8_t len = data.at(options_offset++);

			DOLOG(debug, "CCP option: %02x of %d bytes %s\n", type, len, bin_to_text(data.data() + next_offset, len).c_str());

			if (data.size() - next_offset < len) {
				DOLOG(debug, "len: %d, got: %zu\n", len, data.size() - options_offset);
				break;
			}

			std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(rej));	
			DOLOG(debug, "CCP unknown option %02x\n", type);

			options_offset = next_offset + len;
		}

		// REJ
		if (rej.empty() == false)
			send_rej(0x80fd, data.at(ccp_offset + 1), rej);
		else
			send_ack(0x80fd, data.at(ccp_offset + 1), ack);
	}
}

void phys_ppp::handle_ipcp(const std::vector<uint8_t> & data)
{
	size_t ipcp_offset = 4;

	const uint8_t code = data.at(ipcp_offset + 0);
	const uint8_t identifier = data.at(ipcp_offset + 1);

	uint16_t length = (data.at(ipcp_offset + 2) << 8) | data.at(ipcp_offset + 3);
	DOLOG(debug, "IPCP code %02x identifier %02x length %d\n", code, identifier, length);

	if (data.size() < 4 + length) {
		DOLOG(debug, "IPCP INVALID SIZE %zu < %d\n", data.size(), 4 + 8 + length);
		return;
	}

	if (code == 0x01) {  // options
		std::vector<uint8_t> ack, rej;

		bool send_nak_with_new_address = false;

		size_t options_offset = ipcp_offset + 4;

		while(options_offset < data.size() - 2) {
			size_t next_offset = options_offset;
			uint8_t type = data.at(options_offset++);
			uint8_t len = data.at(options_offset++);

			DOLOG(debug, "IPCP REQ option: %02x of %d bytes (%s)\n", type, len, bin_to_text(data.data() + next_offset, len).c_str());

			if (data.size() - next_offset < len) {
				DOLOG(debug, "IPCP len: %d, got: %zu\n", len, data.size() - options_offset);
				break;
			}

			if (type == 0x03) {  // IP address
				any_addr theirs(data.data() + options_offset, 4);

				if (theirs == opponent_address) {
					DOLOG(debug, "phys_ppp: IPCP acking IP address %s\n", theirs.to_str().c_str());

					std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(ack));
				}
				else {
					DOLOG(debug, "phys_ppp: IPCP send NAK with address %s\n", opponent_address.to_str().c_str());
					send_nak_with_new_address = true;
				}
			}
			else {
				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(rej));	
				DOLOG(debug, "IPCP unknown option %02x: %s\n", type, bin_to_text(data.data() + next_offset, len).c_str());
			}

			options_offset = next_offset + len;
		}

		// REJ
		if (send_nak_with_new_address) {
			assert(opponent_address.get_len() == 4);

			DOLOG(debug, "push IPCP IP addr (addr: %s)\n", opponent_address.to_str().c_str());

			// IP-address
			std::vector<uint8_t> nak;
			nak.push_back(3);
			nak.push_back(6);
			nak.push_back(opponent_address[0]);
			nak.push_back(opponent_address[1]);
			nak.push_back(opponent_address[2]);
			nak.push_back(opponent_address[3]);

			send_nak(0x8021, data.at(ipcp_offset + 1), nak);
		}
		else if (rej.empty() == false) {
			send_rej(0x8021, data.at(ipcp_offset + 1), rej);
		}
		else if (ack.empty() == false) {
			send_ack(0x8021, data.at(ipcp_offset + 1), ack);
		}

		if (!ipcp_options_acked) {
			auto it = prot_map.find(0x800);  // assuming IPv4
			if (it == prot_map.end())
				DOLOG(warning, "phys_ppp: IPCP no IPv4 stack attached to PPP device\n");
			else {
				any_addr a = it->second->get_addr();
				assert(a.get_len() == 4);

				DOLOG(debug, "sending IPCP options (addr: %s)\n", a.to_str().c_str());

				std::vector<uint8_t> out;
				out.push_back(0x01);  // code for 'request'
				out.push_back(1);  // identifier
				size_t len_offset = out.size();
				out.push_back(0);  // length
				out.push_back(0);  // length

				// IP-address
				out.push_back(3);
				out.push_back(6);
				out.push_back(a[0]);
				out.push_back(a[1]);
				out.push_back(a[2]);
				out.push_back(a[3]);

				out.at(len_offset) = out.size() >> 8;
				out.at(len_offset + 1) = out.size() & 255;

				std::vector<uint8_t> out_wrapped = wrap_in_ppp_frame(out, 0x8021, ACCM_tx, false);

				send_lock.lock();
				if (write(fd, out_wrapped.data(), out_wrapped.size()) != out_wrapped.size())
					DOLOG(info, "write error\n");
				send_lock.unlock();
			}
		}
	}
	else if (code == 0x02) {  // options ack
		ipcp_options_acked = true;
	}
	else if (code == 0x04) {  // configure reject
		size_t options_offset = ipcp_offset + 4;

		while(options_offset < data.size() - 2) {
			size_t next_offset = options_offset;
			uint8_t type = data.at(options_offset++);
			uint8_t len = data.at(options_offset++);

			DOLOG(debug, "IPCP REJ option: %02x of %d bytes (%s)\n", type, len, bin_to_text(data.data() + next_offset, len).c_str());

			if (data.size() - next_offset < len) {
				DOLOG(debug, "IPCP len: %d, got: %zu\n", len, data.size() - options_offset);
				break;
			}

			options_offset = next_offset + len;
		}
	}
	else {
		DOLOG(debug, "IPCP: unknown code %02x: %s\n", code, bin_to_text(data.data(), data.size()).c_str());
	}
}

void phys_ppp::handle_ipv6cp(const std::vector<uint8_t> & data)
{
	size_t ipv6cp_offset = 4;

	const uint8_t code = data.at(ipv6cp_offset + 0);
	const uint8_t identifier = data.at(ipv6cp_offset + 1);

	uint16_t length = (data.at(ipv6cp_offset + 2) << 8) | data.at(ipv6cp_offset + 3);
	DOLOG(debug, "IPV6CP code %02x identifier %02x length %d\n", code, identifier, length);

	if (data.size() < 4 + length) {
		DOLOG(debug, "\tINVALID SIZE %zu < %d\n", data.size(), 4 + 8 + length);
		return;
	}

	if (code == 0x01) {  // options
		std::vector<uint8_t> ack, rej;

		size_t options_offset = ipv6cp_offset + 4;

		while(options_offset < data.size() - 2) {
			size_t next_offset = options_offset;
			uint8_t type = data.at(options_offset++);
			uint8_t len = data.at(options_offset++);

			DOLOG(debug, "IPV6CP option: %02x of %d bytes (%s)\n", type, len, bin_to_text(data.data() + next_offset, len).c_str());

			if (data.size() - next_offset < len) {
				DOLOG(debug, "IPV6CP len: %d, got: %zu\n", len, data.size() - options_offset);
				break;
			}

			if (type == 0xff) {  // IP address
			}
			else {
				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(rej));	
				DOLOG(debug, "IPV6CP unknown option %02x: %s\n", type, bin_to_text(data.data() + next_offset, len).c_str());
			}

			options_offset = next_offset + len;
		}

		// REJ
		if (rej.empty() == false) {
			send_rej(0x8057, data.at(ipv6cp_offset + 1), rej);
		}
		else {
			send_ack(0x8057, data.at(ipv6cp_offset + 1), ack);
		}
	}
	else if (code == 0x02) {  // options ack
		ipv6cp_options_acked = true;
	}
}

void phys_ppp::handle_lcp(const std::vector<uint8_t> & data)
{
	size_t lcp_offset = 4;
	const uint8_t code = data.at(lcp_offset + 0);
	const uint8_t identifier = data.at(lcp_offset + 1);

	uint16_t length = (data.at(lcp_offset + 2) << 8) | data.at(lcp_offset + 3);

	DOLOG(debug, "LCP code %02x identifier %02x length %d\n", code, identifier, length);

	if (data.size() < 4 + length) {
		DOLOG(debug, "LCP INVALID SIZE %zu < %d\n", data.size(), 4 + 8 + length);
		return;
	}

	if (code == 0x01) {  // options req
		std::vector<uint8_t> ack, rej;

		size_t options_offset = lcp_offset + 4;

		protocol_compression = false;
		ac_field_compression = false;

		lcp_options_acked = false;

		// -2: last two are the crc
		while(options_offset < data.size() - 2) {
			size_t next_offset = options_offset;
			uint8_t type = data.at(options_offset++);
			uint8_t len = data.at(options_offset++);

			DOLOG(debug, "LCP option: %02x of %d bytes (%s)\n", type, len, bin_to_text(data.data() + next_offset, len).c_str());

			if (data.size() - next_offset < len) {
				DOLOG(debug, "LCP len: %d, got: %zu\n", len, data.size() - options_offset);
				break;
			}

			if (type == 1) {  // max receive unit
				DOLOG(debug, "LCP MTU: %d\n", (data.at(options_offset + 0) << 8) | data.at(options_offset + 1));
				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(ack));	
			}
			else if (type == 2) {  // ACCM
				for(size_t i=0; i<len; i++) {
					// let's do it the same for both directions
					ACCM_rx.at(i) = ACCM_tx.at(i) = data.at(options_offset + i);
				}

				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(ack));	
			}
			else if (type == 5) {  // magic
				// magic = (data.at(options_offset + 0) << 24) | (data.at(options_offset + 1) << 16) | (data.at(options_offset + 2) << 8) | data.at(options_offset + 3);
				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(ack));	
			}
			else if (type == 7) {  // protocol field
				protocol_compression = true;
				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(ack));	
			}
			else if (type == 8) {  // remove address and control field
				ac_field_compression = true;
				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(ack));	
			}
			else if (type == 13) {  // callback 0x0d
				DOLOG(debug, "LCP callback: %02x\n", data.at(options_offset));
				// not supported
				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(rej));	
			}
			else {
				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(rej));	
				DOLOG(debug, "LCP unknown option %02x\n", type);
			}

			options_offset = next_offset + len;
		}

		DOLOG(debug, "send 0x01 LCP reply\n");

		// REJ
		if (rej.empty() == false) {
			send_rej(0xc021, data.at(lcp_offset + 1), rej);
		}
		// ACK
		else if (ack.empty() == false) {
			send_ack(0xc021, identifier, ack);
		}

		// send request
		if (!lcp_options_acked)
		{
			std::vector<uint8_t> out;
			out.push_back(0x01);  // code for 'request'
			out.push_back(1);  // identifier
			size_t len_offset = out.size();
			out.push_back(0);  // length
			out.push_back(0);  // length

			// ACCM
			out.push_back(2);
			out.push_back(6);
			out.push_back(ACCM_rx.at(0));
			out.push_back(ACCM_rx.at(1));
			out.push_back(ACCM_rx.at(2));
			out.push_back(ACCM_rx.at(3));

			// magic 
			out.push_back(5);
			out.push_back(6);
			out.push_back(magic >> 24);
			out.push_back(magic >> 16);
			out.push_back(magic >>  8);
			out.push_back(magic);

			// protocol compression
			out.push_back(7);
			out.push_back(2);

			// address- & control field compression
			out.push_back(8);
			out.push_back(2);

			out.at(len_offset) = out.size() >> 8;
			out.at(len_offset + 1) = out.size() & 255;

			std::vector<uint8_t> out_wrapped = wrap_in_ppp_frame(out, 0xC021, ACCM_tx, false);

			send_lock.lock();
			if (write(fd, out_wrapped.data(), out_wrapped.size()) != out_wrapped.size())
				DOLOG(info, "write error\n");
			send_lock.unlock();
		}
	}
	else if (code == 0x02) {  // options ack
		lcp_options_acked = true;
	}
	else if (code == 0x09) {  // echo request
		DOLOG(debug, "\techo request: %s\n", std::string((const char *)(data.data() + lcp_offset + 8), length - 8).c_str());

		DOLOG(debug, "send 0x09 LCP reply\n");

		std::vector<uint8_t> out;
		out.push_back(10);  // code
		out.push_back(data.at(lcp_offset + 1));  // identifier
		out.push_back(0x00);  // length
		out.push_back(8);  // length
		out.push_back(magic >> 24);
		out.push_back(magic >> 16);
		out.push_back(magic >>  8);
		out.push_back(magic);

		std::vector<uint8_t> out_wrapped = wrap_in_ppp_frame(out, 0xC021, ACCM_tx, false);

		send_lock.lock();
		if (write(fd, out_wrapped.data(), out_wrapped.size()) != out_wrapped.size())
			DOLOG(info, "write error\n");
		send_lock.unlock();
		
	}
	else if (code == 0x0c) {  // identifier (12)
		DOLOG(debug, "\tmessage: %s\n", std::string((const char *)(data.data() + lcp_offset + 8), length - 8).c_str());

		DOLOG(debug, "send 0x0c LCP reply\n");

		std::vector<uint8_t> out;
		out.push_back(0x0c);  // code
		out.push_back(data.at(lcp_offset + 1));  // identifier
		out.push_back(0x00);  // length
		out.push_back(12);  // length
		out.push_back(magic >> 24);
		out.push_back(magic >> 16);
		out.push_back(magic >>  8);
		out.push_back(magic);
		out.push_back('M');
		out.push_back('y');
		out.push_back('I');
		out.push_back('P');

		std::vector<uint8_t> out_wrapped = wrap_in_ppp_frame(out, 0xC021, ACCM_tx, false);

		send_lock.lock();
		if (write(fd, out_wrapped.data(), out_wrapped.size()) != out_wrapped.size())
			DOLOG(info, "write error\n");
		send_lock.unlock();
	}
}

void phys_ppp::operator()()
{
	DOLOG(debug, "phys_ppp: thread started\n");

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

		stats_add_counter(phys_ifInOctets, size);
		stats_add_counter(phys_ifHCInOctets, size);
		stats_inc_counter(phys_ifInUcastPkts);

		if (buffer == 0x7e) {
			if (packet_buffer.empty() == false) {  // START/END of packet
				packet_buffer = unwrap_ppp_frame(packet_buffer, ACCM_rx);

				if (packet_buffer.at(0) != 0xff && ac_field_compression) {
					packet_buffer.insert(packet_buffer.begin()+0, 0xff);
					packet_buffer.insert(packet_buffer.begin()+1, 0x03);
				}

				if ((packet_buffer.at(2) & 1) == 1 && protocol_compression)
					packet_buffer.insert(packet_buffer.begin()+2, 0x00);

				uint16_t protocol = (packet_buffer.at(2) << 8) | packet_buffer.at(3);

				DOLOG(debug, "address: %02x\n", packet_buffer.at(0));
				DOLOG(debug, "control: %02x\n", packet_buffer.at(1));
				DOLOG(debug, "protocol: %04x\n", protocol);

				DOLOG(debug, "size: %zu\n", packet_buffer.size());

				if (protocol == 0x0021) {  // IP
					stats_inc_counter(phys_recv_frame);

					any_addr src_mac((const uint8_t *)"\0\0\0\0\0\1", 6);

					DOLOG(debug, "phys_ppp: queing packet, size %zu\n", packet_buffer.size());

					auto it = prot_map.find(0x800);  // assuming IPv4
					if (it == prot_map.end())
						DOLOG(warning, "phys_ppp: no IPv4 stack attached to PPP device (yet)\n");
					else {
						// 4 ppp header, 2 fcs (=crc)
						packet *p = new packet(src_mac, my_mac, packet_buffer.data() + 4, packet_buffer.size() - (4 + 2), NULL, 0);

						it->second->queue_packet(this, p);
					}
				}
				else if (protocol == 0xc021) {  // LCP
					handle_lcp(packet_buffer);
				}
				else if (protocol == 0x8021) {  // IPCP
					handle_ipcp(packet_buffer);
				}
				else if (protocol == 0x8057) {  // IPV6CP
					handle_ipv6cp(packet_buffer);
				}
				else if (protocol == 0x80fd) {  // CCP
					handle_ccp(packet_buffer);
				}
				else {
					DOLOG(info, "phys_ppp: protocol %04x not supported\n", protocol);
				}

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
						DOLOG(debug, "ATDT -> CONNECT (%s)\n", modem.c_str());
						write(fd, "CONNECT\r\n", 9);
						modem.clear();
					}
					else if (modem.find("AT") != std::string::npos) {
						DOLOG(debug, "AT -> OK (%s)\n", modem.c_str());
						write(fd, "OK\r\n", 4);
						modem.clear();
					}
					else if (modem.find("CLIENT") != std::string::npos) {
						// Windows XP direction PPP connection
						DOLOG(debug, "CLIENT -> SERVER\n");
						write(fd, "SERVER\r\n", 7);
						modem.clear();
					}
				}
			}
		}
	}

	DOLOG(info, "phys_ppp: thread stopped\n");
}
