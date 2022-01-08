#include <atomic>
#include <thread>

#include "tcp.h"

class socks_proxy
{
private:
	std::thread *th { nullptr };
	std::atomic_bool stop_flag { false };
	tcp *const t { nullptr };

	int fd { -1 };

public:
	socks_proxy(const std::string & interface, const int port, tcp *const t);
	virtual ~socks_proxy();

	void operator()();
};
