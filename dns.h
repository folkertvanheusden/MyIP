#pragma once

#include <condition_variable>
#include <map>
#include <mutex>

#include "any_addr.h"
#include "application.h"
#include "udp.h"


typedef struct {
	any_addr a;
	time_t   t;
	int      max_age;
} dns_a_rec_t;

typedef struct {
	std::string name;
	time_t      t;
	int         max_age;
} dns_cname_rec_t;

class dns : public application
{
private:
	udp *const u                      { nullptr };

	const any_addr my_ip;
	const any_addr dns_ip;

	std::thread *th                   { nullptr };

	uint64_t *dns_queries             { nullptr };
	uint64_t *dns_queries_hit         { nullptr };
	uint64_t *dns_queries_miss        { nullptr };
	uint64_t *dns_queries_alien_reply { nullptr };
	uint64_t *dns_queries_to          { nullptr };

	std::mutex                         lock;
	std::map<std::string, dns_a_rec_t> a_aaaa_cache;
	std::map<std::string, dns_cname_rec_t> cname_cache;
	std::condition_variable            updated;

public:
	dns(stats *const s, udp *const u, const any_addr & my_ip, const any_addr & dns_ip);
	virtual ~dns();

	// verify if packet comes from 'dns_a'!
	void input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, session_data *const pd);

	// send query to dns, wait for 'updated' and then
	// check if set in chache. if not, wait. upto to ms.
	std::optional<any_addr> query(const std::string & hostname, const int to);

	// flush cache periodically
	void operator()();
};
