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
