// (C) 2022-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
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
#include "phys_gen_ppp.h"
#include "packet.h"
#include "str.h"
#include "utils.h"


any_addr gen_opponent_mac(const any_addr & my_mac)
{
	uint8_t src_mac_bin[6] { 0 };

	for(int i=0; i<6; i++)
		src_mac_bin[i] = my_mac[i] ^ ((i & 1) ? 0x55 : 0xaa);

	return any_addr(any_addr::mac, src_mac_bin);
}

phys_gen_ppp::phys_gen_ppp(const size_t dev_index, stats *const s, const std::string & name, const any_addr & my_mac, const any_addr & opponent_address, router *const r) :
	phys(dev_index, s, "ppp-" + name, r),
	my_mac(my_mac),
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

phys_gen_ppp::~phys_gen_ppp()
{
}

void phys_gen_ppp::start()
{
	th = new std::thread(std::ref(*this));
}

std::vector<uint8_t> phys_gen_ppp::wrap_in_ppp_frame(const std::vector<uint8_t> & payload, const uint16_t protocol, const std::vector<uint8_t> & ACCM, const bool not_ppp_meta)
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
	CDOLOG(ll_debug, "[ppp]", "ppp pkt before: %s\n", d.c_str());

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
	CDOLOG(ll_debug, "[ppp]", "ppp pkt after: %s\n", d.c_str());

	return out;
}

void phys_gen_ppp::send_Xcp(const uint8_t code, const uint8_t identifier, const uint16_t protocol, const std::vector<uint8_t> & data)
{
	CDOLOG(ll_debug, "[ppp]", "ppp send code %d\n", code);

	std::vector<uint8_t> out;

	out.push_back(code);
	out.push_back(identifier);

	size_t len_offset = out.size();
	out.push_back(0);  // placeholder for length (MSB)
	out.push_back(0);  // placeholder for length (LSB)

	std::copy(data.begin(), data.end(), std::back_inserter(out));

	out.at(len_offset) = out.size() >> 8;
	out.at(len_offset + 1) = out.size() & 255;

	transmit_low(out, protocol, ACCM_tx, false);
}

void phys_gen_ppp::send_rej(const uint16_t protocol, const uint8_t identifier, const std::vector<uint8_t> & options)
{
	CDOLOG(ll_debug, "[ppp]", "ppp send rej for protocol %04x, identifier %02x\n", protocol, identifier);

	send_Xcp(4, identifier, protocol, options);
}

void phys_gen_ppp::send_ack(const uint16_t protocol, const uint8_t identifier, const std::vector<uint8_t> & options)
{
	CDOLOG(ll_debug, "[ppp]", "ppp send ack for protocol %04x, identifier %02x\n", protocol, identifier);

	send_Xcp(2, identifier, protocol, options);
}

void phys_gen_ppp::send_nak(const uint16_t protocol, const uint8_t identifier, const std::vector<uint8_t> & options)
{
	CDOLOG(ll_debug, "[ppp]", "ppp send nak for protocol %04x, identifier %02x\n", protocol, identifier);

	send_Xcp(3, identifier, protocol, options);
}

void phys_gen_ppp::handle_ccp(const std::vector<uint8_t> & data)
{
	size_t ccp_offset = 4;

	const uint8_t code = data.at(ccp_offset + 0);
	const uint8_t identifier = data.at(ccp_offset + 1);

	uint16_t length = (data.at(ccp_offset + 2) << 8) | data.at(ccp_offset + 3);
	CDOLOG(ll_debug, "[ppp]", "CCP code %02x identifier %02x length %d\n", code, identifier, length);

	if (data.size() < 4 + length) {
		CDOLOG(ll_debug, "[ppp]", "\tINVALID SIZE %zu < %d\n", data.size(), 4 + 8 + length);
		return;
	}

	if (code == 0x01) {  // options
		std::vector<uint8_t> ack, rej;

		CDOLOG(ll_debug, "[ppp]", "\tOPTIONS:\n");

		size_t options_offset = ccp_offset + 4;

		while(options_offset < data.size() - 2) {
			size_t next_offset = options_offset;
			uint8_t type = data.at(options_offset++);
			uint8_t len = data.at(options_offset++);

			CDOLOG(ll_debug, "[ppp]", "CCP option: %02x of %d bytes %s\n", type, len, bin_to_text(data.data() + next_offset, len, false).c_str());

			if (data.size() - next_offset < len) {
				CDOLOG(ll_debug, "[ppp]", "len: %d, got: %zu\n", len, data.size() - options_offset);
				break;
			}

			std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(rej));	
			CDOLOG(ll_debug, "[ppp]", "CCP unknown option %02x\n", type);

			options_offset = next_offset + len;
		}

		// REJ
		if (rej.empty() == false)
			send_rej(0x80fd, data.at(ccp_offset + 1), rej);
		else
			send_ack(0x80fd, data.at(ccp_offset + 1), ack);
	}
}

void phys_gen_ppp::handle_ipcp(const std::vector<uint8_t> & data)
{
	size_t ipcp_offset = 4;

	const uint8_t code = data.at(ipcp_offset + 0);
	const uint8_t identifier = data.at(ipcp_offset + 1);

	uint16_t length = (data.at(ipcp_offset + 2) << 8) | data.at(ipcp_offset + 3);
	CDOLOG(ll_debug, "[ppp]", "IPCP code %02x identifier %02x length %d\n", code, identifier, length);

	if (data.size() < 4 + length) {
		CDOLOG(ll_debug, "[ppp]", "IPCP INVALID SIZE %zu < %d\n", data.size(), 4 + 8 + length);
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

			CDOLOG(ll_debug, "[ppp]", "IPCP REQ option: %02x of %d bytes (%s)\n", type, len, bin_to_text(data.data() + next_offset, len, false).c_str());

			if (data.size() - next_offset < len) {
				CDOLOG(ll_debug, "[ppp]", "IPCP len: %d, got: %zu\n", len, data.size() - options_offset);
				break;
			}

			if (type == 0x03) {  // IP address
				any_addr theirs(any_addr::ipv4, data.data() + options_offset);

				if (theirs == opponent_address) {
					CDOLOG(ll_debug, "[ppp]", "IPCP acking IP address %s\n", theirs.to_str().c_str());

					std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(ack));
				}
				else {
					CDOLOG(ll_debug, "[ppp]", "IPCP send NAK with address %s\n", opponent_address.to_str().c_str());
					send_nak_with_new_address = true;
				}
			}
			else {
				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(rej));	
				CDOLOG(ll_debug, "[ppp]", "IPCP unknown option %02x: %s\n", type, bin_to_text(data.data() + next_offset, len, false).c_str());
			}

			options_offset = next_offset + len;
		}

		// REJ
		if (send_nak_with_new_address) {
			assert(opponent_address.get_len() == 4);

			CDOLOG(ll_debug, "[ppp]", "push IPCP IP addr (addr: %s)\n", opponent_address.to_str().c_str());

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
				CDOLOG(ll_warning, "[ppp]", "IPCP no IPv4 stack attached to PPP device\n");
			else {
				any_addr a = it->second->get_addr();
				assert(a.get_len() == 4);

				CDOLOG(ll_debug, "[ppp]", "sending IPCP options (addr: %s)\n", a.to_str().c_str());

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

				transmit_low(out, 0x8021, ACCM_tx, false);
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

			CDOLOG(ll_debug, "[ppp]", "IPCP REJ option: %02x of %d bytes (%s)\n", type, len, bin_to_text(data.data() + next_offset, len, false).c_str());

			if (data.size() - next_offset < len) {
				CDOLOG(ll_debug, "[ppp]", "IPCP len: %d, got: %zu\n", len, data.size() - options_offset);
				break;
			}

			options_offset = next_offset + len;
		}
	}
	else {
		CDOLOG(ll_debug, "[ppp]", "IPCP: unknown code %02x: %s\n", code, bin_to_text(data.data(), data.size(), false).c_str());
	}
}

void phys_gen_ppp::handle_ipv6cp(const std::vector<uint8_t> & data)
{
	size_t ipv6cp_offset = 4;

	const uint8_t code = data.at(ipv6cp_offset + 0);
	const uint8_t identifier = data.at(ipv6cp_offset + 1);

	uint16_t length = (data.at(ipv6cp_offset + 2) << 8) | data.at(ipv6cp_offset + 3);
	CDOLOG(ll_debug, "[ppp]", "IPV6CP code %02x identifier %02x length %d\n", code, identifier, length);

	if (data.size() < 4 + length) {
		CDOLOG(ll_debug, "[ppp]", "\tINVALID SIZE %zu < %d\n", data.size(), 4 + 8 + length);
		return;
	}

	if (code == 0x01) {  // options
		std::vector<uint8_t> ack, rej;

		size_t options_offset = ipv6cp_offset + 4;

		while(options_offset < data.size() - 2) {
			size_t next_offset = options_offset;
			uint8_t type = data.at(options_offset++);
			uint8_t len = data.at(options_offset++);

			CDOLOG(ll_debug, "[ppp]", "IPV6CP option: %02x of %d bytes (%s)\n", type, len, bin_to_text(data.data() + next_offset, len, false).c_str());

			if (data.size() - next_offset < len) {
				CDOLOG(ll_debug, "[ppp]", "IPV6CP len: %d, got: %zu\n", len, data.size() - options_offset);
				break;
			}

			if (type == 0xff) {  // IP address
			}
			else {
				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(rej));	
				CDOLOG(ll_debug, "[ppp]", "IPV6CP unknown option %02x: %s\n", type, bin_to_text(data.data() + next_offset, len, false).c_str());
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

void phys_gen_ppp::handle_lcp(const std::vector<uint8_t> & data)
{
	size_t lcp_offset = 4;
	const uint8_t code = data.at(lcp_offset + 0);
	const uint8_t identifier = data.at(lcp_offset + 1);

	uint16_t length = (data.at(lcp_offset + 2) << 8) | data.at(lcp_offset + 3);

	CDOLOG(ll_debug, "[ppp]", "LCP code %02x identifier %02x length %d\n", code, identifier, length);

	if (data.size() < 4 + length) {
		CDOLOG(ll_debug, "[ppp]", "LCP INVALID SIZE %zu < %d\n", data.size(), 4 + 8 + length);
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

			CDOLOG(ll_debug, "[ppp]", "LCP option: %02x of %d bytes (%s)\n", type, len, bin_to_text(data.data() + next_offset, len, false).c_str());

			if (data.size() - next_offset < len) {
				CDOLOG(ll_debug, "[ppp]", "LCP len: %d, got: %zu\n", len, data.size() - options_offset);
				break;
			}

			if (type == 1) {  // max receive unit
				CDOLOG(ll_debug, "[ppp]", "LCP MTU: %d\n", (data.at(options_offset + 0) << 8) | data.at(options_offset + 1));
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
				CDOLOG(ll_debug, "[ppp]", "LCP callback: %02x\n", data.at(options_offset));
				// not supported
				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(rej));	
			}
			else {
				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(rej));	
				CDOLOG(ll_debug, "[ppp]", "LCP unknown option %02x\n", type);
			}

			options_offset = next_offset + len;
		}

		CDOLOG(ll_debug, "[ppp]", "send 0x01 LCP reply\n");

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

			transmit_low(out, 0xC021, ACCM_tx, false);
		}
	}
	else if (code == 0x02) {  // options ack
		lcp_options_acked = true;
	}
	else if (code == 0x09) {  // echo request
		CDOLOG(ll_debug, "[ppp]", "\techo request: %s\n", std::string((const char *)(data.data() + lcp_offset + 8), length - 8).c_str());

		CDOLOG(ll_debug, "[ppp]", "send 0x09 LCP reply\n");

		std::vector<uint8_t> out;
		out.push_back(10);  // code
		out.push_back(data.at(lcp_offset + 1));  // identifier
		out.push_back(0x00);  // length
		out.push_back(8);  // length
		out.push_back(magic >> 24);
		out.push_back(magic >> 16);
		out.push_back(magic >>  8);
		out.push_back(magic);

		transmit_low(out, 0xC021, ACCM_tx, false);
	}
	else if (code == 0x0c) {  // identifier (12)
		CDOLOG(ll_debug, "[ppp]", "\tmessage: %s\n", std::string((const char *)(data.data() + lcp_offset + 8), length - 8).c_str());

		CDOLOG(ll_debug, "[ppp]", "send 0x0c LCP reply\n");

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

		transmit_low(out, 0xC021, ACCM_tx, false);
	}
}

void phys_gen_ppp::process_incoming_packet(std::vector<uint8_t> packet_buffer, const struct timespec & ts)
{
	if (packet_buffer.size() < 4) {
		CDOLOG(ll_debug, "[ppp]", "packet too small: dropped (size %zu)\n", packet_buffer.size());
		return;
	}

	if (packet_buffer.at(0) != 0xff && ac_field_compression) {
		packet_buffer.insert(packet_buffer.begin()+0, 0xff);
		packet_buffer.insert(packet_buffer.begin()+1, 0x03);
	}

	if ((packet_buffer.at(2) & 1) == 1 && protocol_compression)
		packet_buffer.insert(packet_buffer.begin()+2, 0x00);

	uint16_t protocol = (packet_buffer.at(2) << 8) | packet_buffer.at(3);

	CDOLOG(ll_debug, "[ppp]", "address: %02x\n", packet_buffer.at(0));
	CDOLOG(ll_debug, "[ppp]", "control: %02x\n", packet_buffer.at(1));
	CDOLOG(ll_debug, "[ppp]", "protocol: %04x\n", protocol);

	CDOLOG(ll_debug, "[ppp]", "size: %zu\n", packet_buffer.size());

	if (protocol == 0x0021) {  // IP
		stats_inc_counter(phys_recv_frame);

		any_addr src_mac = gen_opponent_mac(my_mac);

		CDOLOG(ll_debug, "[ppp]", "queing packet, size %zu\n", packet_buffer.size());

		auto it = prot_map.find(0x800);  // assuming IPv4
		if (it == prot_map.end())
			CDOLOG(ll_warning, "[ppp]", "no IPv4 stack attached to PPP device (yet)\n");
		else {
			// 4 ppp header, 2 fcs (=crc)
			packet *p = new packet(ts, src_mac, my_mac, packet_buffer.data() + 4, packet_buffer.size() - (4 + 2), NULL, 0, "PPP[]");

			it->second->queue_incoming_packet(this, p);
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
		CDOLOG(ll_info, "[ppp]", "protocol %04x not supported\n", protocol);
	}
}

bool phys_gen_ppp::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size)
{
	CDOLOG(ll_debug, "[ppp]", "transmit_packet: %s -> %s over %s\n",
			src_mac.to_str().c_str(), dst_mac.to_str().c_str(), to_str().c_str());

        std::vector<uint8_t> temp(payload, &payload[pl_size]);

        stats_add_counter(phys_ifOutOctets,   pl_size);
        stats_add_counter(phys_ifHCOutOctets, pl_size);
        stats_inc_counter(phys_ifOutUcastPkts);

        return transmit_low(temp, 0x0021 /* IP */, ACCM_tx, true);
}
