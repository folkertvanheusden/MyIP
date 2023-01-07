#pragma once

#include <condition_variable>
#include <mutex>
#include <stdint.h>


uint64_t get_us();
uint64_t get_ms();
uint32_t ms_since_midnight();

void myusleep(uint64_t us);

class interruptable_sleep
{
private:
	std::mutex              lock;
	std::condition_variable cv;
	bool                    stop { false };

public:
	interruptable_sleep();

	void signal_stop();

	// returns true when stop is set
	bool sleep(const uint32_t ms);
};
