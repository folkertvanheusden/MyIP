// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <optional>
#include <stdint.h>
#include <string>
#include <vector>

void swap_mac(uint8_t *a, uint8_t *b);
void swap_ipv4(uint8_t *a, uint8_t *b);

uint8_t *duplicate(const uint8_t *const in, const size_t size);

uint64_t get_us();
uint64_t get_ms();
void myusleep(uint64_t us);

void get_random(uint8_t *tgt, size_t n);

std::string myformat(const char *const fmt, ...);
std::vector<std::string> split(std::string in, std::string splitter);
std::string replace(std::string target, const std::string & what, const std::string & by_what);
std::string bin_to_text(const uint8_t *p, const size_t len);
std::string merge(const std::vector<std::string> & in, const std::string & seperator);
std::string str_tolower(std::string s);
std::optional<std::string> find_header(const std::vector<std::string> *const lines, const std::string & key, const std::string & seperator = ":");

uint8_t * get_from_buffer(uint8_t **p, size_t *len, size_t get_len);

typedef enum { debug, info, warning, ll_error } log_level_t;  // TODO ll_ prefix
void setlog(const char *lf, const log_level_t ll_file, const log_level_t ll_screen);
void setloguid(const int uid, const int gid);
void closelog();
void dolog(const log_level_t ll, const char *fmt, ...);
#define DOLOG(ll, fmt, ...) do {				\
	extern log_level_t log_level_file, log_level_screen;	\
								\
	if (ll >= log_level_file || ll >= log_level_screen)	\
		dolog(ll, fmt, ##__VA_ARGS__);			\
	} while(0)

void set_thread_name(std::string name);
bool file_exists(const std::string & file, size_t *const file_size = nullptr);
void run(const std::string & what);

uint64_t MurmurHash64A(const void *const key, const int len, const uint64_t seed);
std::string md5hex(const std::string & in);

uint32_t crc32(const uint8_t *const data, const size_t n_data, const uint32_t polynomial);

void error_exit(const bool se, const char *format, ...);
