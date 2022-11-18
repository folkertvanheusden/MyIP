#pragma once

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
