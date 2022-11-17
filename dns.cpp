#include <chrono>
#include <string>
#include <thread>
#include <vector>
#include <arpa/inet.h>

#include "dns.h"
#include "log.h"
#include "str.h"
#include "time.h"
#include "udp.h"
#include "utils.h"


using namespace std::chrono_literals;

dns::dns(stats *const s, udp *const u, const any_addr & my_ip, const any_addr & dns_ip) : u(u), my_ip(my_ip), dns_ip(dns_ip)
{
	dns_queries             = s->register_stat("dns_queries",       "1.3.6.1.2.1.4.57850.1.12.1");
	dns_queries_hit         = s->register_stat("dns_queries_hit",   "1.3.6.1.2.1.4.57850.1.12.2");
	dns_queries_miss        = s->register_stat("dns_queries_miss",  "1.3.6.1.2.1.4.57850.1.12.3");
	dns_queries_alien_reply = s->register_stat("dns_queries_alien", "1.3.6.1.2.1.4.57850.1.12.4");
	dns_queries_to          = s->register_stat("dns_queries_to",    "1.3.6.1.2.1.4.57850.1.12.5");

	th = new std::thread(std::ref(*this));
}

dns::~dns()
{
	th->join();
	delete th;
}

std::pair<std::string, int> get_name(const uint8_t *const base, const uint8_t *const buffer, const bool first)
{
	std::string name;
	int         tl   = 0;  // total len

	for(;;) {
		uint8_t len = buffer[tl++];

		if (len == 0)
			break;

		if (len & 0xc0) {  // "compression"
			uint16_t offset = ((len & ~0xc0) << 8) | buffer[tl++];
			printf("offset %d, len: %d\n", offset, base[offset]);

			// apparently it is only 1 level deep, this compression
			if (first) {
				auto sub = get_name(base, &base[offset], false);

				name += sub.first;
			}

			break;
		}
		else {
			std::string out = std::string((const char *)&buffer[tl], len);
			printf("sub[%d]: %s\n", len, out.c_str());
			tl += len;

			name += out + ".";
		}
	}

	return { name, tl };
}

// verify if packet comes from 'dns_ip'!
void dns::input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, void *const pd)
{
	if (src_ip != dns_ip) {
		DOLOG(info, "DNS response from unexpected address (%s)\n", src_ip.to_str().c_str());
		stats_inc_counter(dns_queries_alien_reply);
		return;
	}

	const uint16_t *const header = (const uint16_t *)p->get_data();

	if (ntohs(header[1]) == 0x8400) {  // standard query response, no error
		DOLOG(debug, "DNS query response: %04x\n", ntohs(header[1]));
		return;
	}

	uint16_t qdcount = ntohs(header[2]);  // query count
	uint16_t ancount = ntohs(header[3]);  // answers
	//uint16_t nscount = ntohs(header[4]);  // nameservers
	//uint16_t arcount = ntohs(header[5]);  // additional information

	const uint8_t *work_p = (const uint8_t *)&header[6];

	DOLOG(debug, "DNS QDCOUNT: %d\n", qdcount);

	for(int i=0; i<qdcount; i++) {
		auto name_len = get_name(p->get_data(), work_p, true);
		work_p += name_len.second;

		uint16_t type = (work_p[0] << 8) | work_p[1];
		work_p += 2;

		uint16_t class_ = (work_p[0] << 8) | work_p[1];
		work_p += 2;

		DOLOG(debug, "DNS QD name: %s / qtype: %04x / class: %04x\n", name_len.first.c_str(), type, class_);
	}

	DOLOG(debug, "DNS ANCOUNT: %d\n", ancount);

	for(int i=0; i<ancount; i++) {
		auto name_len = get_name(p->get_data(), work_p, true);
		work_p += name_len.second;

		uint16_t type = (work_p[0] << 8) | work_p[1];
		work_p += 2;

		uint16_t class_ = (work_p[0] << 8) | work_p[1];
		work_p += 2;

		int ttl = (work_p[0] << 24) | (work_p[1] << 16) | (work_p[2] << 8) | work_p[3];
		work_p += 4;

		uint16_t len = (work_p[0] << 8) | work_p[1];
		work_p += 2;

		if (len == 4 && type == 0x0001 /* type A */) {
			any_addr a(work_p, len);
			dns_rec_t dr { a, p->get_recv_ts().tv_sec, ttl };

			std::string name = name_len.first.substr(0, name_len.first.size() - 1);  // remove '.'

			DOLOG(debug, "DNS: Mapping %s to %s\n", name.c_str(), a.to_str().c_str());

			std::unique_lock lck(lock);

			cache.insert_or_assign(name, dr);
		}
		else {
			DOLOG(debug, "DNS: type: %04x, class: %04x, len: %d for %s\n", type, class_, len, name_len.first.c_str());
		}
	}

	updated.notify_all();
}

using namespace std::chrono_literals;

// send query to dns, wait for 'updated' and then
// check if set in chache. if not, wait. upto to ms.
std::optional<any_addr> dns::query(const std::string & name, const int to)
{
	std::string work = str_tolower(name);

	stats_inc_counter(dns_queries);

	auto wait_until  = std::chrono::system_clock::now() + 1ms * to;

	bool first       = true;

	std::unique_lock lck(lock);

	do {
		auto   it  = cache.find(work);

		time_t now = time(nullptr);

		if (it != cache.end() && now - it->second.t < it->second.max_age) {
			stats_inc_counter(dns_queries_miss);

			return it->second.a;
		}

		if (first) {
			first = false;

			stats_inc_counter(dns_queries_miss);

			uint8_t buffer[256] { 0 };
			int     offset = 0;

			buffer[offset++] = 0;  // transaction id
			buffer[offset++] = 0;

			buffer[offset++] = 1;  // request with recursion
			buffer[offset++] = 0;

			buffer[offset++] = 0;  // 1 query
			buffer[offset++] = 1;

			buffer[offset++] = 0;  // answer rr
			buffer[offset++] = 0;

			buffer[offset++] = 0;  // authority rr
			buffer[offset++] = 0;

			buffer[offset++] = 0;  // additional rr
			buffer[offset++] = 0;

			// name
			std::vector<std::string> parts = split(work, ".");
			for(auto & p : parts) {
				buffer[offset++] = p.size();
				memcpy(&buffer[offset], p.data(), p.size());
				offset += p.size();
			}
			buffer[offset++] = 0;  // no more address parts

			// qtype
			buffer[offset++] = 0;  // host address
			buffer[offset++] = 1;

			// qclass
			buffer[offset++] = 0;  // host address
			buffer[offset++] = 1;

			u->transmit_packet(dns_ip, 53, my_ip, 53, buffer, offset);
		}

	}
	while (updated.wait_until(lck, wait_until) != std::cv_status::timeout);

	stats_inc_counter(dns_queries_to);

	return { };
}

// flush cache periodically
void dns::operator()()
{
	set_thread_name("myip-dns");

	int count = 0;

	while(!stop_flag) {
		myusleep(500000);

		if (++count < 60) // flush every 30s
			continue;

		count = 0;

		std::unique_lock lck(lock);

		if (cache.size() > 1024) {
			time_t now = time(nullptr);

			for(auto it = cache.begin(); it != cache.end();) {
				if (now - it->second.t >= it->second.max_age)
					it = cache.erase(it);
				else
					it++;
			}
		}
	}
}
