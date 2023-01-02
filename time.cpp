#include <chrono>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>


uint64_t get_us()
{
	struct timespec ts { 0, 0 };

	if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		fprintf(stderr, "clock_gettime failed: %s\n", strerror(errno));

	return uint64_t(ts.tv_sec) * uint64_t(1000000l) + uint64_t(ts.tv_nsec / 1000);
}

uint64_t get_ms()
{
	struct timespec ts { 0, 0 };

	if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		fprintf(stderr, "clock_gettime failed: %s\n", strerror(errno));

	return uint64_t(ts.tv_sec) * uint64_t(1000) + uint64_t(ts.tv_nsec / 1000000);
}

uint32_t ms_since_midnight()
{
	auto   now  = std::chrono::system_clock::now();

	time_t tnow = std::chrono::system_clock::to_time_t(now);

	tm *date = std::localtime(&tnow);
	date->tm_hour = 0;
	date->tm_min  = 0;
	date->tm_sec  = 0;

	auto midnight   = std::chrono::system_clock::from_time_t(std::mktime(date));

	auto difference = now - midnight;

	return std::chrono::duration_cast<std::chrono::milliseconds>(difference).count();
}

void myusleep(uint64_t us)
{
	struct timespec req;

	req.tv_sec = us / 1000000l;
	req.tv_nsec = (us % 1000000l) * 1000l;

	for(;;) {
		struct timespec rem { 0, 0 };

		int rc = nanosleep(&req, &rem);
		if (rc == 0 || (rc == -1 && errno != EINTR))
			break;

		memcpy(&req, &rem, sizeof(struct timespec));
	}
}
