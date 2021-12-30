// (C) 2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
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

#include "phys_ppp.h"
#include "packet.h"
#include "utils.h"

phys_ppp::phys_ppp(stats *const s, const std::string & dev_name, const int bps, const any_addr & my_mac) : phys_slip(s, dev_name, bps, my_mac)
{
	ACCM_rx.resize(32);
	ACCM_rx.at(0) = 0xff;
	ACCM_rx.at(1) = 0xff;
	ACCM_rx.at(2) = 0xff;
	ACCM_rx.at(3) = 0xff;
	ACCM_rx.at(0x7e >> 3) = 0x7e & 7;  // flag
	ACCM_rx.at(0x7d >> 3) = 0x7e & 7;  // escape character

	ACCM_tx = ACCM_rx;  // initially only
}

phys_ppp::~phys_ppp()
{
}

void phys_ppp::start()
{
	th = new std::thread(std::ref(*this));
}

std::vector<uint8_t> wrap_in_ppp_frame(const std::vector<uint8_t> & payload, const uint16_t protocol, const std::vector<uint8_t> ACCM)
{
	std::vector<uint8_t> temp;

	temp.push_back(0xff);  // standard broadcast address
	temp.push_back(0x03);  // unnumbered data
	temp.push_back(protocol >> 8);  // protocol
	temp.push_back(protocol);  // protocol
	std::copy(payload.begin(), payload.end(), std::back_inserter(temp));	
	// TODO? padding?

	// from https://stackoverflow.com/questions/4308606/how-do-i-create-an-fcs-for-ppp-packets
	uint16_t crc = 0xffff;

	for(size_t loop=0; loop<temp.size(); loop++) {
		uint8_t x = temp.at(loop);

		for(int i=0; i<8; i++) {
			crc=((crc&1)^(x&1))?(crc>>1)^0x8408:crc>>1;
			x>>=1;
		}
	}

	temp.push_back(crc >> 8);
	temp.push_back(crc);

	std::vector<uint8_t> out;
	out.push_back(0x7e);  // flag

	for(size_t i=0; i<temp.size(); i++) {
		uint8_t b = temp.at(i);

		if (ACCM.at(b >> 3) & (1 << (b & 7))) {
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

std::vector<uint8_t> unwrap_ppp_frame(const std::vector<uint8_t> & payload, const std::vector<uint8_t> ACCM)
{
	std::vector<uint8_t> out;

	for(size_t i=0; i<payload.size();) {
		uint8_t c = payload.at(i++);

		if (c == 0x7d)
			out.push_back(payload.at(i++) ^ 0x20);
		else
			out.push_back(c);
	}

	return out;
}

bool phys_ppp::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *payload, const size_t pl_size)
{
	return true;
	std::vector temp(payload, &payload[pl_size]);
	std::vector<uint8_t> ppp_frame = wrap_in_ppp_frame(temp, 0x0021 /* IP */, ACCM_tx);

	bool ok = true;

	send_lock.lock();
	int rc = write(fd, ppp_frame.data(), ppp_frame.size());
	send_lock.unlock();

	if (size_t(rc) != ppp_frame.size()) {
		dolog(error, "phys_ppp: problem sending packet (%d for %zu bytes)\n", rc, ppp_frame.size());

		if (rc == -1)
			dolog(error, "phys_ppp: %s\n", strerror(errno));

		ok = false;
	}

	return ok;
}

void phys_ppp::handle_lcp(const std::vector<uint8_t> & data)
{
	size_t lcp_offset = 4;
	uint8_t code = data.at(lcp_offset + 0);

	dolog(debug, "LCP:\n");
	dolog(debug, "\tcode: %02x\n", code);
	dolog(debug, "\tidentifier: %02x\n", data.at(lcp_offset + 1));
	uint16_t length = (data.at(lcp_offset + 2) << 8) | data.at(lcp_offset + 3);
	dolog(debug, "\tlength: %d\n", length);
	uint32_t magic = 0;
	//uint32_t magic = (data.at(lcp_offset + 4) << 24) | (data.at(lcp_offset + 5) << 16) | (data.at(lcp_offset + 6) << 8) | data.at(lcp_offset + 7);
	//dolog(debug, "\tmagic: %08x\n", magic);

	if (data.size() < 4 + length) {
		dolog(debug, "\tINVALID SIZE %zu < %d\n", data.size(), 4 + 8 + length);
		return;
	}

	if (code == 0x01) {  // options
		dolog(debug, "\tOPTIONS:\n");
		size_t options_offset = lcp_offset + 8;

		std::vector<uint8_t> ack, nak;

		while(options_offset < data.size()) {
			size_t next_offset = options_offset;
			uint8_t type = data.at(options_offset++);
			uint8_t len = data.at(options_offset++);

			if (len == 0)
				continue;

			if (len < 2 || data.size() - options_offset < len - 2) {
				dolog(debug, "len: %d, got: %zu\n", len, data.size() - options_offset);
				break;
			}

			if (type == 1) {  // max receive unit
				dolog(debug, "\t\tMTU: %d\n", (data.at(options_offset + 0) << 8) | data.at(options_offset + 1));
				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(ack));	
			}
			else if (type == 5) {  // magic
				magic = (data.at(options_offset + 0) << 24) | (data.at(options_offset + 1) << 16) | (data.at(options_offset + 2) << 8) | data.at(options_offset + 3);
				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(ack));	
			}
			else {
				std::copy(data.begin() + next_offset, data.begin() + next_offset + len, std::back_inserter(nak));	
				dolog(debug, "\t\tunknown option %02x\n", type);
			}

			options_offset = next_offset + len;
		}

		dolog(debug, "send 0x01 LCP reply\n");

		// ACK
		{
			std::vector<uint8_t> out;
			out.push_back(0x02);  // code for 'ack'
			out.push_back(data.at(lcp_offset + 1));  // identifier
			size_t len_offset = out.size();
			out.push_back(0);  // length
			out.push_back(0);  // length

			std::copy(ack.begin(), ack.end(), std::back_inserter(out));	

			out.at(len_offset) = out.size() >> 8;
			out.at(len_offset + 1) = out.size() & 255;

			std::vector<uint8_t> out_wrapped = wrap_in_ppp_frame(out, 0xC021, ACCM_tx);

			send_lock.lock();
			if (write(fd, out_wrapped.data(), out_wrapped.size()) != out_wrapped.size())  // TODO error checking, locking
				printf("write error\n");
			send_lock.unlock();
		}

		// REJECT
		if (nak.empty() == false) {
			std::vector<uint8_t> out;
			out.push_back(0x04);  // code for 'reject'
			out.push_back(data.at(lcp_offset + 1));  // identifier
			size_t len_offset = out.size();
			out.push_back(0);  // length
			out.push_back(0);  // length

			std::copy(nak.begin(), nak.end(), std::back_inserter(out));	

			out.at(len_offset) = out.size() >> 8;
			out.at(len_offset + 1) = out.size() & 255;

			std::vector<uint8_t> out_wrapped = wrap_in_ppp_frame(out, 0xC021, ACCM_tx);

			send_lock.lock();
			if (write(fd, out_wrapped.data(), out_wrapped.size()) != out_wrapped.size())
				printf("write error\n");
			send_lock.unlock();
		}

		// send request
		{
			std::vector<uint8_t> out;
			out.push_back(0x01);  // code for 'reject'
			out.push_back(rand() & 255);  // identifier
			size_t len_offset = out.size();
			out.push_back(0);  // length
			out.push_back(0);  // length

			// max mtu size
			out.push_back(1);
			out.push_back(4);
			out.push_back(1500 >> 8);
			out.push_back(1500 & 255);

			out.at(len_offset) = out.size() >> 8;
			out.at(len_offset + 1) = out.size() & 255;

			std::vector<uint8_t> out_wrapped = wrap_in_ppp_frame(out, 0xC021, ACCM_tx);

			send_lock.lock();
			if (write(fd, out_wrapped.data(), out_wrapped.size()) != out_wrapped.size())
				printf("write error\n");
			send_lock.unlock();
		}
	}
	else if (code == 0x12) {  // identifier
		dolog(debug, "\tmessage: %s\n", std::string((const char *)(data.data() + lcp_offset + 8), length).c_str());

		dolog(debug, "send 0x12 LCP reply\n");

		std::vector<uint8_t> out;
		out.push_back(0x12);  // code
		out.push_back(data.at(lcp_offset + 1));  // identifier
		out.push_back(0x00);  // length
		out.push_back(12);  // length
		out.push_back(data.at(lcp_offset + 4));  // magic number
		out.push_back(data.at(lcp_offset + 5));
		out.push_back(data.at(lcp_offset + 6));
		out.push_back(data.at(lcp_offset + 7));
		out.push_back('M');
		out.push_back('y');
		out.push_back('I');
		out.push_back('P');

		std::vector<uint8_t> out_wrapped = wrap_in_ppp_frame(out, 0xC021, ACCM_tx);

		send_lock.lock();
		if (write(fd, out_wrapped.data(), out_wrapped.size()) != out_wrapped.size())
			printf("write error\n");
		send_lock.unlock();
	}
}

void phys_ppp::operator()()
{
	dolog(debug, "phys_ppp: thread started\n");

	set_thread_name("myip-phys_ppp");

	std::vector<uint8_t> packet_buffer;

	struct pollfd fds[] = { { fd, POLLIN, 0 } };

	while(!stop_flag) {
		int rc = poll(fds, 1, 150);
		if (rc == -1) {
			if (errno == EINTR)
				continue;

			dolog(error, "poll: %s", strerror(errno));
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
				packet_buffer = unwrap_ppp_frame(packet_buffer, ACCM_rx);

				dolog(debug, "address: %02x\n", packet_buffer.at(0));
				dolog(debug, "control: %02x\n", packet_buffer.at(1));
				uint16_t protocol = (packet_buffer.at(2) << 8) | packet_buffer.at(3);
				dolog(debug, "protocol: %04x\n", protocol);
				dolog(debug, "size: %zu\n", packet_buffer.size());

				for(size_t i=4; i<packet_buffer.size() - 2; i++)
					printf("%02x ", packet_buffer.at(i));
				printf("\n");

				if (protocol == 0x0021) {  // IP
					stats_inc_counter(phys_recv_frame);

					any_addr src_mac((const uint8_t *)"\0\0\0\0\0\1", 6);

					dolog(debug, "phys_ppp: queing packet, size %zu\n", packet_buffer.size());

					// 4 ppp header, 2 fcs (=crc)
					packet *p = new packet(src_mac, my_mac, packet_buffer.data() + 4, packet_buffer.size() - (4 + 2), NULL, 0);

					auto it = prot_map.find(0x800);  // assuming IPv4
					if (it == prot_map.end())
						dolog(warning, "phys_ppp: no IPv4 stack attached to PPP device (yet)\n");
					else
						it->second->queue_packet(this, p);
				}
				else if (protocol == 0xc021) {  // LCP
					handle_lcp(packet_buffer);
				}

				packet_buffer.clear();
			}
		}
		else {
			packet_buffer.push_back(buffer);
		}
	}

	dolog(info, "phys_ppp: thread stopped\n");
}
