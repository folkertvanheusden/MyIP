// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <algorithm>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <vector>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#include <sys/syscall.h>
#define gettid() pid_t(syscall(SYS_gettid))
#endif

#include "utils.h"

void swap_mac(uint8_t *a, uint8_t *b)
{
	uint8_t temp[6];
	memcpy(temp, a, 6);
	memcpy(a, b, 6);
	memcpy(b, temp, 6);
}

void swap_ipv4(uint8_t *a, uint8_t *b)
{
	uint8_t temp[4];
	memcpy(temp, a, 4);
	memcpy(a, b, 4);
	memcpy(b, temp, 4);
}

uint8_t *duplicate(const uint8_t *const in, const size_t size)
{
	uint8_t *out = new uint8_t[size];
	memcpy(out, in, size);

	return out;
}

std::string myformat(const char *const fmt, ...)
{
        char *buffer = nullptr;
        va_list ap;

        va_start(ap, fmt);
        (void)vasprintf(&buffer, fmt, ap);
        va_end(ap);

        std::string result = buffer;
        free(buffer);

        return result;
}

uint64_t get_us()
{
	struct timeval tv { 0, 0 };
	gettimeofday(&tv, nullptr);

	return tv.tv_sec * 1000l * 1000l + tv.tv_usec;
}

void get_random(uint8_t *tgt, size_t n)
{
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1) {
		dolog(error, "open(\"/dev/urandom\"): %s", strerror(errno));
		exit(1);
	}

	while(n > 0) {
		int rc = read(fd, tgt, n);

		if (rc == -1) {
			if (errno == EINTR)
				continue;

			dolog(error, "read(\"/dev/urandom\"): %s", strerror(errno));
			exit(1);
		}

		tgt += rc;
		n -= rc;
	}

	close(fd);
}

std::vector<std::string> * split(std::string in, std::string splitter)
{
	std::vector<std::string> *out = new std::vector<std::string>;
	size_t splitter_size = splitter.size();

	for(;;)
	{
		size_t pos = in.find(splitter);
		if (pos == std::string::npos)
			break;

		std::string before = in.substr(0, pos);
		out -> push_back(before);

		size_t bytes_left = in.size() - (pos + splitter_size);
		if (bytes_left == 0)
		{
			out -> push_back("");
			return out;
		}

		in = in.substr(pos + splitter_size);
	}

	if (in.size() > 0)
		out -> push_back(in);

	return out;
}

static const char *logfile = strdup("/tmp/myip.log");
static log_level_t log_level_file = warning;
static log_level_t log_level_screen = warning;
static FILE *lfh = nullptr;

void setlog(const char *lf, const log_level_t ll_file, const log_level_t ll_screen)
{
	if (lfh)
		fclose(lfh);

	free((void *)logfile);

	logfile = strdup(lf);

	log_level_file = ll_file;
	log_level_screen = ll_screen;
}

void dolog(const log_level_t ll, const char *fmt, ...)
{
	if (ll < log_level_file && ll < log_level_screen)
		return;

	if (!lfh) {
		lfh = fopen(logfile, "a+");

		if (!lfh)
			fprintf(stderr, "Cannot access log-file %s: %s\n", logfile, strerror(errno));
	}

	uint64_t now = get_us();
	time_t t_now = now / 1000000;

	struct tm tm { 0 };
	localtime_r(&t_now, &tm);

	char *ts_str = nullptr;

	const char *const ll_names[] = { "debug  ", "info   ", "warning", "error  " };

	asprintf(&ts_str, "%04d-%02d-%02d %02d:%02d:%02d.%06d %.6f|%d] %s ",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, int(now % 1000000),
			get_us() / 1000000.0, gettid(), ll_names[ll]);

	char *str = nullptr;

	va_list ap;
	va_start(ap, fmt);
	(void)vasprintf(&str, fmt, ap);
	va_end(ap);

	if (ll >= log_level_file) {
		fprintf(lfh, "%s%s", ts_str, str);
		fflush(lfh);
	}

	if (ll >= log_level_screen)
		printf("%s%s", ts_str, str);

	free(str);
	free(ts_str);
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

	dolog(debug, "Set name of thread %d to \"%s\"\n", gettid(), name.c_str());

	pthread_setname_np(pthread_self(), name.c_str());
}

std::string bin_to_text(const uint8_t *p, const size_t len)
{
	char *temp = (char *)calloc(1, len * 6 + 1);

	for(size_t i=0; i<len; i++)
		snprintf(&temp[i * 6], 7, "%c[%02x] ", p[i] > 32 && p[i] < 127 ? p[i] : '.', p[i]);

	std::string out = temp;

	free(temp);

	return out;
}

bool file_exists(const std::string & file, size_t *const file_size)
{
	struct stat st { 0 };

	bool rc = stat(file.c_str(), &st) == 0;

	if (rc && file_size)
		*file_size = st.st_size;

	return rc;
}

void myusleep(uint64_t us)
{
	struct timespec req;

	req.tv_sec = us / 1000000l;
	req.tv_nsec = (us % 1000000l) * 1000l;

	for(;;) {
		struct timespec rem { 0, 0 };

		if (nanosleep(&req, &rem) == 0)
			break;

		memcpy(&req, &rem, sizeof(struct timespec));
	}
}

std::string str_tolower(std::string s)
{
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });

	return s;
}

std::optional<std::string> find_header(const std::vector<std::string> *const lines, const std::string & key)
{
	const std::string lkey = str_tolower(key);
	std::optional<std::string> value;

	for(auto line : *lines) {
		auto parts = split(line, ":");

		if (parts->size() == 2 && str_tolower(parts->at(0)) == lkey) {
			value = parts->at(1);

			while(value.value().empty() == false && value.value().at(0) == ' ')
				value = value.value().substr(1);
		}

		delete parts;
	}

	return value;
}

std::string merge(const std::vector<std::string> & in, const std::string & seperator)
{
	std::string out;

	for(auto l : in)
		out += l + seperator;

	return out;
}
