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
		ask_to_stop();
	}

	void ask_to_stop() {
		stop_flag = true;
	}
};
