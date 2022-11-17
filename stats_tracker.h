// (C) 2017-2022 by folkert van heusden, released under Apache License v2.0
#pragma once

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <thread>
#include <sys/resource.h>
#include <sys/time.h>


class stats_tracker
{
private:
	int      prev_slot_ru { -1 };
	uint64_t prev_ru_ts   { 0  };

	struct rusage latest_ru { 0 };
	struct rusage prev_ru   { 0 };

	double cpu_stats[5] { 0. };

	std::thread *th { nullptr };

	std::condition_variable cv_stop;
	mutable std::mutex      m;
	bool                    cv_stop_notify { false };

public:
	stats_tracker();
	virtual ~stats_tracker();

	void operator()();

	double get_cpu_usage() const;
};
