#include <stdio.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "mdns.h"
#include "utils.h"


constexpr int ttl = 5;

uint16_t add_ptr(uint8_t *const tgt, const std::vector<std::string> & name)
{
	uint16_t o = 0;

	// svc name
	for(size_t i=1; i<name.size(); i++) {
		tgt[o++] = name.at(i).size();

		o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(i).c_str());
	}

	tgt[o++] = 0x00;

	tgt[o++] = 0x00;  // PTR (12)
	tgt[o++] = 0x0c;

	tgt[o++] = 0x00;  // class: in
	tgt[o++] = 0x01;

	tgt[o++] = ttl >> 24;  // ttl
	tgt[o++] = ttl >> 16;
	tgt[o++] = ttl >> 8;
	tgt[o++] = ttl;

	uint16_t ptr_data_len = 1;

	for(size_t i=0; i<name.size(); i++)
		ptr_data_len += name.at(i).size() + 1;

	tgt[o++] = ptr_data_len >> 8;
	tgt[o++] = ptr_data_len;

	// name itself
	for(size_t i=0; i<name.size(); i++) {
		tgt[o++] = name.at(i).size();

		o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(i).c_str());
	}

	tgt[o++] = 0x00;

	return o;
}

uint16_t add_srv(uint8_t *const tgt, const std::vector<std::string> & name, const int port)
{
	uint16_t o = 0;

	// name itself
	for(size_t i=0; i<name.size(); i++) {
		tgt[o++] = name.at(i).size();

		o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(i).c_str());
	}

	tgt[o++] = 0;  // string delimiter

	tgt[o++] = 0x00;  // type 33 SRV (server selection)
	tgt[o++] = 0x21;

	tgt[o++] = 0x80;  // class (class: cache flush, in)
	tgt[o++] = 0x01;

	tgt[o++] = ttl >> 24;  // ttl
	tgt[o++] = ttl >> 16;
	tgt[o++] = ttl >> 8;
	tgt[o++] = ttl;

	uint16_t srv_data_len = 2 + 2 + 2 + 1 + name.at(0).size() + 1 + 5 /* "local" */ + 1;
	tgt[o++] = srv_data_len >> 8;  // data len
	tgt[o++] = srv_data_len;

	tgt[o++] = 0x00;  // priority
	tgt[o++] = 0x00;

	tgt[o++] = 0x00;  // weight
	tgt[o++] = 0x00;

	tgt[o++] = port >> 8;  // port on which it listens
	tgt[o++] = port;

	tgt[o++] = name.at(0).size();
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(0).c_str());

	tgt[o++] = 5;
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "local");

	tgt[o++] = 0x00;

	return o;
}

uint16_t add_a(uint8_t *const tgt, const std::vector<std::string> & name, const any_addr & a)
{
	uint16_t o = 0;

	tgt[o++] = name.at(0).size();
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(0).c_str());

	tgt[o++] = 5;
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "local");

	tgt[o++] = 0;  // string delimiter

	tgt[o++] = 0x00;  // type 0001 (A)
	tgt[o++] = 0x01;

	tgt[o++] = 0x80;  // class (cache flush: True, class: in)
	tgt[o++] = 0x01;

	tgt[o++] = ttl >> 24;  // ttl
	tgt[o++] = ttl >> 16;
	tgt[o++] = ttl >> 8;
	tgt[o++] = ttl;

	tgt[o++] = 0x00;  // length of address
	tgt[o++] = a.get_len();

	for(int i=0; i<a.get_len(); i++)
		tgt[o++] = a[i];

	return o;
}

uint16_t add_txt(uint8_t *const tgt, const std::vector<std::string> & name)
{
	uint16_t o = 0;

	for(size_t i=0; i<name.size(); i++) {
		tgt[o++] = name.at(i).size();

		o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(i).c_str());
	}

	tgt[o++] = 0;  // string delimiter

	tgt[o++] = 0x00;  // type 16 SRV (server selection)
	tgt[o++] = 0x10;

	tgt[o++] = 0x80;  // class (class: cache flush, in)
	tgt[o++] = 0x01;

	tgt[o++] = ttl >> 24;  // ttl
	tgt[o++] = ttl >> 16;
	tgt[o++] = ttl >> 8;
	tgt[o++] = ttl;

	tgt[o++] = 0;  // data len
	tgt[o++] = 0;

	return o;
}

uint16_t add_nsec(uint8_t *const tgt, const std::vector<std::string> & name)
{
	uint16_t o = 0;

	tgt[o++] = name.at(0).size();
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(0).c_str());

	tgt[o++] = 5;
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "local");

	tgt[o++] = 0;  // string delimiter

	tgt[o++] = 0x00;  // type 47 (NSEC)
	tgt[o++] = 0x2f;

	tgt[o++] = 0x00;  // class (class: in)
	tgt[o++] = 0x01;

	tgt[o++] = ttl >> 24;  // ttl
	tgt[o++] = ttl >> 16;
	tgt[o++] = ttl >> 8;
	tgt[o++] = ttl;

	uint16_t data_len = 1 + name.at(0).size() + 1 + 5/*"local"*/ + 1 + 2 + 6;
	tgt[o++] = data_len >> 8;  // length of nsec
	tgt[o++] = data_len;

	tgt[o++] = name.at(0).size();
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(0).c_str());

	tgt[o++] = 5;
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "local");

	tgt[o++] = 0;  // string delimiter

	tgt[o++] = 0x00;  // window
	tgt[o++] = 0x06;  // bitmap len

	uint16_t bm_o = o;
	tgt[o++] = 0x00;
	tgt[o++] = 0x00;
	tgt[o++] = 0x00;
	tgt[o++] = 0x00;
	tgt[o++] = 0x00;
	tgt[o++] = 0x00;

	tgt[bm_o + 1  / 8] |= 1 << (7 - (1  % 8));  // A
	tgt[bm_o + 12 / 8] |= 1 << (7 - (12 % 8));  // PTR
	tgt[bm_o + 16 / 8] |= 1 << (7 - (16 % 8));  // TXT
	tgt[bm_o + 33 / 8] |= 1 << (7 - (33 % 8));  // SRV
	tgt[bm_o + 47 / 8] |= 1 << (7 - (47 % 8));  // NSEC

	return o;
}

mdns::mdns()
{
	th = new std::thread(std::ref(*this));
}

mdns::~mdns()
{
	stop_flag = true;

	th->join();
	delete th;
}

void mdns::add_protocol(udp *const interface, const int port, const std::string & hostname)
{
	std::unique_lock lck(lock);

	protocols.push_back({ interface, port, hostname });
}

void mdns::operator()()
{
	while(!stop_flag) {
		sleep(5);

		DOLOG(debug, "MDNS: transmit %zu records\n", protocols.size());

		constexpr uint8_t mc_addr[] { 224, 0, 0, 251 };

		any_addr dst_ip(mc_addr, sizeof mc_addr);

		std::unique_lock<std::mutex> lck(lock);

		for(auto tgt : protocols) {
			uint8_t  mdns_buffer[256] { 0 };
			uint16_t ro               { 0 };

			mdns_buffer[ro++] = 0x00;  // transaction id
			mdns_buffer[ro++] = 0x00;

			mdns_buffer[ro++] = 0x84;  // standard query response, no error
			mdns_buffer[ro++] = 0x00;

			mdns_buffer[ro++] = 0x00;  // 0 questions
			mdns_buffer[ro++] = 0x00;

			mdns_buffer[ro++] = 0x00;  // 3 answers
			mdns_buffer[ro++] = 0x03;

			mdns_buffer[ro++] = 0x00;  // 0 authority rr
			mdns_buffer[ro++] = 0x00;
			
			mdns_buffer[ro++] = 0x00;  // 0 additional rr
			mdns_buffer[ro++] = 0x00;

			std::string hostname  = tgt.hostname;
			std::size_t last_char = hostname.size() - 1;

			if (hostname[last_char] == '.')
				hostname.erase(last_char);

			auto name = split(hostname, ".");

			printf("len: %zu\n", name.size());
			for(auto & p : name)
				printf("part %s\n", p.c_str());

			// PTR record
			ro += add_ptr(&mdns_buffer[ro], name);

			// TXT record
			ro += add_txt(&mdns_buffer[ro], name);

			// SRV midi record
			ro += add_srv(&mdns_buffer[ro], name, tgt.port);

			any_addr src_addr = tgt.interface->get_ip_address();

			// A record for the hostname to the ip-address
			ro += add_a(&mdns_buffer[ro], name, src_addr);

			if (!tgt.interface->transmit_packet(dst_ip, 5353, src_addr, 5353, mdns_buffer, ro))
				DOLOG(warning, "MDNS: failed to transmit MDNS record for %s\n", src_addr.to_str().c_str());
		}
	}
}
