#include <atomic>
#include <string>
#include <thread>

#include "any_addr.h"
#include "udp.h"


class sip_register
{
private:
	udp *const u;
	const std::string upstream_server, username, password;
	const any_addr myip;
	const int myport;

	std::thread *th { nullptr };
	std::atomic_bool stop_flag { false };

public:
	sip_register(udp *const u, const std::string & upstream_sip_server, const std::string & upstream_sip_user, const std::string & upstream_sip_password, const any_addr & myip, const int myport);
	virtual ~sip_register();

	void operator()();
};
