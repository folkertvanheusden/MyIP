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
#include <openssl/md5.h>
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
	struct timespec ts { 0, 0 };

	if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		fprintf(stderr, "clock_gettime failed: %s\n", strerror(errno));

	return uint64_t(ts.tv_sec) * uint64_t(1000000l) + uint64_t(ts.tv_nsec / 1000);
}

void get_random(uint8_t *tgt, size_t n)
{
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
		n -= rc;
	}

	close(fd);
}

std::vector<std::string> split(std::string in, std::string splitter)
{
	std::vector<std::string> out;
	size_t splitter_size = splitter.size();

	for(;;)
	{
		size_t pos = in.find(splitter);
		if (pos == std::string::npos)
			break;

		std::string before = in.substr(0, pos);
		out.push_back(before);

		size_t bytes_left = in.size() - (pos + splitter_size);
		if (bytes_left == 0)
		{
			out.push_back("");
			return out;
		}

		in = in.substr(pos + splitter_size);
	}

	if (in.size() > 0)
		out.push_back(in);

	return out;
}

static const char *logfile = strdup("/tmp/myip.log");
log_level_t log_level_file = warning;
log_level_t log_level_screen = warning;
static FILE *lfh = nullptr;
static int lf_uid = 0, lf_gid = 0;

void setlog(const char *lf, const log_level_t ll_file, const log_level_t ll_screen)
{
	if (lfh)
		fclose(lfh);

	free((void *)logfile);

	logfile = strdup(lf);

	log_level_file = ll_file;
	log_level_screen = ll_screen;
}

void setloguid(const int uid, const int gid)
{
	lf_uid = uid;
	lf_gid = gid;
}

void closelog()
{
	fclose(lfh);
	lfh = nullptr;
}

void dolog(const log_level_t ll, const char *fmt, ...)
{
	if (ll < log_level_file && ll < log_level_screen)
		return;

	if (!lfh) {
		lfh = fopen(logfile, "a+");
		if (!lfh) {
			fprintf(stderr, "Cannot access log-file %s: %s\n", logfile, strerror(errno));
			exit(1);
		}

		if (fchown(fileno(lfh), lf_uid, lf_gid) == -1)
			fprintf(stderr, "Cannot change logfile (%s) ownership: %s\n", logfile, strerror(errno));

		if (fcntl(fileno(lfh), F_SETFD, FD_CLOEXEC) == -1) {
			fprintf(stderr, "fcntl(FD_CLOEXEC): %s\n", strerror(errno));
			exit(1);
		}
	}

	uint64_t now = get_us();
	time_t t_now = now / 1000000;

	struct tm tm { 0 };
	if (!localtime_r(&t_now, &tm))
		fprintf(stderr, "localtime_r: %s\n", strerror(errno));

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

	if (ll >= log_level_file)
		fprintf(lfh, "%s%s", ts_str, str);

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

	DOLOG(debug, "Set name of thread %d to \"%s\"\n", gettid(), name.c_str());

	pthread_setname_np(pthread_self(), name.c_str());
}

std::string bin_to_text(const uint8_t *p, const size_t len)
{
	char *temp = (char *)calloc(1, len * 6 + 1);

	for(size_t i=0; i<len; i++)
		// snprintf(&temp[i * 6], 7, "%c[%02x] ", p[i] > 32 && p[i] < 127 ? p[i] : '.', p[i]);
		snprintf(&temp[i * 3], 7, "%s%02x", i ? " " : "", p[i]);

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

std::optional<std::string> find_header(const std::vector<std::string> *const lines, const std::string & key, const std::string & seperator)
{
	const std::string lkey = str_tolower(key);
	std::optional<std::string> value;

	for(auto line : *lines) {
		auto parts = split(line, seperator);

		if (parts.size() >= 2 && str_tolower(parts.at(0)) == lkey) {
			value = line.substr(key.size() + 1);

			while(value.value().empty() == false && value.value().at(0) == ' ')
				value = value.value().substr(1);
		}
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

std::string md5hex(const std::string & in)
{
	unsigned char result[MD5_DIGEST_LENGTH];

	MD5((unsigned char *)in.c_str(), in.size(), result);

	std::string rc;
	for(int i=0; i<MD5_DIGEST_LENGTH; i++)
		rc += myformat("%02x", result[i]);

	return rc;
}

std::string replace(std::string target, const std::string & what, const std::string & by_what)
{
	for(;;) {
		std::size_t found = target.find(what);

		if (found == std::string::npos)
			break;

		std::string before = target.substr(0, found);

		std::size_t after_offset = found + what.size();
		std::string after = target.substr(after_offset);

		target = before + by_what + after;
	}

	return target;
}

void run(const std::string & what)
{
	pid_t pid = fork();

	if (pid == 0)
		exit(system(what.c_str()));

	else if (pid == -1)
		DOLOG(ll_error, "Failed invoking \"%s\"", what.c_str());
}

uint64_t MurmurHash64A(const void *const key, const int len, const uint64_t seed)
{
	const uint64_t m = 0xc6a4a7935bd1e995LLU;
	const int r = 47;

	uint64_t h = seed ^ (len * m);

	const uint64_t *data = (const uint64_t *)key;
	const uint64_t *end = (len >> 3) + data;

	while(data != end) {
		uint64_t k = *data++;

		k *= m;
		k ^= k >> r;
		k *= m;

		h ^= k;
		h *= m;
	}

	const uint8_t *data2 = (const uint8_t *)data;

	switch(len & 7) {
		case 7: h ^= (uint64_t)(data2[6]) << 48;
		case 6: h ^= (uint64_t)(data2[5]) << 40;
		case 5: h ^= (uint64_t)(data2[4]) << 32;
		case 4: h ^= (uint64_t)(data2[3]) << 24;
		case 3: h ^= (uint64_t)(data2[2]) << 16;
		case 2: h ^= (uint64_t)(data2[1]) << 8;
		case 1: h ^= (uint64_t)(data2[0]);
			h *= m;
	};

	h ^= h >> r;
	h *= m;
	h ^= h >> r;

	return h;
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
