// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <algorithm>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <vector>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#include <sys/syscall.h>
#define gettid() pid_t(syscall(SYS_gettid))
#endif

#include "log.h"
#include "time.h"


uint8_t *duplicate(const uint8_t *const in, const size_t size)
{
	uint8_t *out = new uint8_t[size];
	memcpy(out, in, size);

	return out;
}

void get_random(uint8_t *tgt, size_t n)
{
#ifdef linux
	while(n > 0) {
		ssize_t rc = getrandom(tgt, n, 0);

		if (rc <= 0) {
			if (errno == EINTR)
				continue;

			DOLOG(ll_error, "getrandom: %s", strerror(errno));
			exit(1);
		}

		tgt += rc;
		n   -= rc;
	}
#else
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1) {
		DOLOG(ll_error, "open(\"/dev/urandom\"): %s", strerror(errno));
		exit(1);
	}

	while(n > 0) {
		int rc = read(fd, tgt, n);

		if (rc == -1) {
			if (errno == EINTR)
				continue;

			DOLOG(ll_error, "read(\"/dev/urandom\"): %s", strerror(errno));
			exit(1);
		}

		tgt += rc;
		n   -= rc;
	}

	close(fd);
#endif
}

uint8_t * get_from_buffer(uint8_t **p, size_t *len, size_t get_len)
{
	if (get_len > *len)
		return nullptr;

	uint8_t *out = (uint8_t *)malloc(get_len);
	memcpy(out, &(*p)[0], get_len);

	size_t left = *len - get_len;

	if (left) {
		memmove(&(*p)[0], &(*p)[get_len], left);
		*len -= get_len;
		assert(*len == left);
	}
	else {
		*len = 0;

		free(*p);
		*p = nullptr;
	}

	return out;
}

void set_thread_name(std::string name)
{
	if (name.length() > 15)
		name = name.substr(0, 15);

	DOLOG(ll_debug, "Set name of thread %d to \"%s\"\n", gettid(), name.c_str());

	pthread_setname_np(pthread_self(), name.c_str());
}

bool file_exists(const std::string & file, size_t *const file_size)
{
	struct stat st { 0 };

	bool rc = stat(file.c_str(), &st) == 0;

	if (rc && file_size)
		*file_size = st.st_size;

	return rc;
}

void run(const std::string & what)
{
	system(what.c_str());
}

void error_exit(const bool se, const char *format, ...)
{
	int e = errno;
	va_list ap;

	va_start(ap, format);
	char *temp = NULL;
	if (vasprintf(&temp, format, ap) == -1)
		puts(format);  // last resort
	va_end(ap);

	fprintf(stderr, "%s\n", temp);
	DOLOG(ll_error, "%s\n", temp);

	if (se && e) {
		fprintf(stderr, "errno: %d (%s)\n", e, strerror(e));
		DOLOG(ll_error, "errno: %d (%s)\n", e, strerror(e));
	}

	free(temp);

	exit(EXIT_FAILURE);
}
