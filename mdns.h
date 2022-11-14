// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#pragma once

#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "application.h"
#include "udp.h"


class mdns : public application
{
private:
	struct entry {
		udp        *interface;
		int         port;
		std::string hostname;
	};

	std::vector<entry> protocols;
	std::mutex         lock;

	std::thread *      th { nullptr };

public:
	mdns();
	mdns(const mdns &) = delete;
	virtual ~mdns();

	void add_protocol(udp *const u, const int port, const std::string & host);

	void operator()();
};
