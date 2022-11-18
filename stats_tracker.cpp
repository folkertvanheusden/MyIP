// (C) 2017-2022 by folkert van heusden, released under Apache License v2.0

#include <cstring>

#include "error.h"
#include "stats_tracker.h"
#include "time.h"
#include "utils.h"


stats_tracker::stats_tracker()
{
	th = new std::thread(std::ref(*this));
}

stats_tracker::~stats_tracker()
{
	if (th) {
		m.lock();

		cv_stop_notify = true;

		cv_stop.notify_one();

		m.unlock();

		th->join();

		delete th;
	}
}

void stats_tracker::operator()()
{
	set_thread_name("stats-tracker");

	for(;;) {
		std::unique_lock<std::mutex> lock(m);

		cv_stop.wait_for(lock, std::chrono::milliseconds(999));

		if (cv_stop_notify)
			break;

		uint64_t now       = get_us();
		int      slot_base = now / 1000000;
		int      slot      = slot_base % 5;

		uint64_t latest_ru_ts = get_us();

		getrusage(RUSAGE_SELF, &latest_ru);  // TODO error checking

		if (prev_ru_ts) {
			if (prev_slot_ru != slot) {
				cpu_stats[slot] = 0;

				prev_slot_ru = slot;
			}

			struct timeval total_time_used { 0, 0 };
			timeradd(&latest_ru.ru_utime, &latest_ru.ru_stime, &total_time_used);

			struct timeval prev_time_used { 0, 0 };
			timeradd(&prev_ru.ru_utime, &prev_ru.ru_stime, &prev_time_used);

			struct timeval diff_time_used { 0, 0 };
			timersub(&total_time_used, &prev_time_used, &diff_time_used);

			double period = (latest_ru_ts - prev_ru_ts) / 1000000.0;

			cpu_stats[slot] += diff_time_used.tv_sec + diff_time_used.tv_usec / 1000000.0 * period;
		}

		prev_ru_ts = latest_ru_ts;
		prev_ru    = latest_ru;
	}
}

double stats_tracker::get_cpu_usage() const
{
	std::unique_lock<std::mutex> lock(m);

	uint64_t now = get_us();
	int slot = (now / 1000000) % 5;

	double total = 0.;

	for(int i=0; i<5; i++) {
		if (i == slot)
			continue;

		total += cpu_stats[i];
	}

	double avg = total / 4;

	return avg;
}
