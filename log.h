#pragma once

#include <string>

#include "str.h"


typedef enum { ll_debug, ll_info, ll_warning, ll_error } log_level_t;

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

#define CDOLOG(ll, context, fmt, ...) do {			\
	extern log_level_t log_level_file, log_level_screen;	\
								\
	if (ll >= log_level_file || ll >= log_level_screen) {	\
		std::string __log_temp = myformat(fmt, ##__VA_ARGS__);\
		dolog(ll, "%s %s", context, __log_temp.c_str()); \
	}							\
} while(0)
