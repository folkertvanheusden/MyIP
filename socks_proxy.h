#include <atomic>
#include <thread>

#include "dns.h"
#include "tcp.h"

class socks_proxy
{
private:
	std::thread *th { nullptr };
	std::atomic_bool stop_flag { false };
	tcp *const t { nullptr };
	dns *dns_ { nullptr };

	int fd { -1 };

public:
	socks_proxy(const std::string & interface, const int port, tcp *const t);
	virtual ~socks_proxy();

	void register_dns(dns *const dns_) { this->dns_ = dns_; }

	void operator()();
};
