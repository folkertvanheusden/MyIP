#pragma once

#include <atomic>

class application
{
protected:
	std::atomic_bool stop_flag { false };

public:
	application() {
	}

	virtual ~application() {
		stop_flag = true;
	}
};
