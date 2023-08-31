#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>


class duration_events
{
private:
	mutable std::mutex lock;
	// duration, timestamp
	std::vector<std::pair<uint64_t, uint64_t> > events;
	const std::string  name;
	const size_t       max_size;

public:
	duration_events(const std::string name, const int max_size);

	void insert(const uint64_t duration);

	auto get() const;
};
