#include "duration_events.h"
#include "log.h"
#include "time.h"


duration_events::duration_events(const std::string name, const int max_size) : name(name), max_size(max_size)
{
	events.resize(max_size);
}

void duration_events::insert(const uint64_t duration)
{
	std::unique_lock<std::mutex> lck(lock);

	if (events.at(0).first < duration) {
		DOLOG(ll_info, "duration_events(%s): %zu\n", name.c_str(), size_t(duration));
		events.insert(events.begin(), { duration, get_us() });

		events.resize(max_size);
	}
}

auto duration_events::get() const
{
	std::unique_lock<std::mutex> lck(lock);

	return events;
}
