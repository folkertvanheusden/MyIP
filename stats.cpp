// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <algorithm>
#include <assert.h>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "stats.h"
#include "stats-utils.h"
#include "utils.h"

constexpr char shm_name[] = "/myip";

void stats_inc_counter(uint64_t *const p)
{
#if defined(GCC_VERSION) && GCC_VERSION >= 40700
	__atomic_add_fetch(p, 1, __ATOMIC_SEQ_CST);
#else
	(*p)++; // hope for the best
#endif
}

void stats_add_average(uint64_t *const p, const int val)
{
#if defined(GCC_VERSION) && GCC_VERSION >= 40700
	// there's a small window where the values are
	// not in sync
	__atomic_add_fetch(p + 1, 1, __ATOMIC_SEQ_CST);
	__atomic_add_fetch(p, val, __ATOMIC_SEQ_CST);
#else
	// hope for the best
	(*(p + 1))++;
	(*p) += val;
#endif
}


stats::stats(const int size) : size(size)
{
	fd = shm_open(shm_name, O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		dolog(error, "shm_open: %s", strerror(errno));
		exit(1);
	}

	if (ftruncate(fd, size) == -1) {
		dolog(error, "truncate: %s", strerror(errno));
		exit(1);
	}

	p = (uint8_t *)mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		dolog(error, "mmap: %s", strerror(errno));
		exit(1);
	}

	memset(p, 0x00, size);

	close(fd);
}

stats::~stats()
{
	dolog(debug, "Removing shared memory segment");
	munmap(p, size);

	shm_unlink(shm_name);
}

uint64_t * stats::register_stat(const std::string & name, const std::string & oid)
{
	if (len + 40 > size) {
		dolog(error, "stats: shm is full\n");
		return nullptr;
	}

	lock.lock();

	auto it = lut.find(name);
	if (it != lut.end()) {
		uint64_t *rc = it->second.p;
		lock.unlock();

		return rc;
	}

	uint8_t *p_out = (uint8_t *)&p[len];

	// hopefully this platform allows atomic updates
	// not using locking, for speed
	*(uint64_t *)p_out = 0;
	*(uint64_t *)(p_out + 8) = 0;

	int copy_n = std::min(name.size(), size_t(23));
	memcpy(&p_out[16], name.c_str(), copy_n);
	p_out[16 + copy_n] = 0x00;

	len += 40;

	stats_t st;
	st.p = reinterpret_cast<uint64_t *>(p_out);
	st.oid = oid;

	auto rc = lut.insert(std::pair<std::string, stats_t>(name, st));
	assert(rc.second);

	if (oid.empty() == false) {
		auto rc2 = lut_oid.insert(std::pair<std::string, uint64_t *>(oid, st.p));
		assert(rc2.second);
	}

	lock.unlock();

	return (uint64_t *)p_out;
}

std::string stats::to_json() const
{
	return stats_to_json(p, size);
}

uint64_t stats::find_by_oid(const std::string & oid)
{
	lock.lock();

	auto rc = lut_oid.find(oid);

	lock.unlock();

	if (rc != lut_oid.end())
		return *rc->second;

	return -1;
}
