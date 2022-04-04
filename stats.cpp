// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <cstring>
#include <fcntl.h>
#include <iterator>
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

void stats_add_counter(uint64_t *const p, const uint16_t value)
{
#if defined(GCC_VERSION) && GCC_VERSION >= 40700
	__atomic_add_fetch(p, value, __ATOMIC_SEQ_CST);
#else
	(*p) += value; // hope for the best
#endif
}

void stats_set(uint64_t *const p, const uint64_t value)
{
	// TODO atomic
	*p = value;
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

stats::stats(const int size, snmp_data *const sd) :
	size(size),
	sd(sd)
{
	fd = shm_open(shm_name, O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		DOLOG(ll_error, "shm_open: %s", strerror(errno));
		exit(1);
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		DOLOG(ll_error, "fcntl(FD_CLOEXEC): %s", strerror(errno));
		exit(1);
	}

	if (ftruncate(fd, size) == -1) {
		DOLOG(ll_error, "truncate: %s", strerror(errno));
		exit(1);
	}

	p = (uint8_t *)mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		DOLOG(ll_error, "mmap: %s", strerror(errno));
		exit(1);
	}

	memset(p, 0x00, size);

	close(fd);
}

stats::~stats()
{
	DOLOG(debug, "Removing shared memory segment\n");
	munmap(p, size);

	shm_unlink(shm_name);
}

uint64_t * stats::register_stat(const std::string & name, const std::string & oid)
{
	if (len + 48 > size) {
		DOLOG(ll_error, "stats: shm is full\n");
		return nullptr;
	}

	std::unique_lock<std::mutex> lck(lock);

	auto lut_it = lut.find(name);
	if (lut_it != lut.end())
		return lut_it->second.p;

	uint8_t *p_out = (uint8_t *)&p[len];

	// hopefully this platform allows atomic updates
	// not using locking, for speed
	*(uint64_t *)p_out = 0;
	*(uint64_t *)(p_out + 8) = 0;

	int copy_n = std::min(name.size(), size_t(31));
	memcpy(&p_out[16], name.c_str(), copy_n);
	p_out[16 + copy_n] = 0x00;

	len += 48;

	if (oid.empty() == false)
		sd->register_oid(oid + ".0", new snmp_data_type_stats(reinterpret_cast<uint64_t *>(p_out)));

	return reinterpret_cast<uint64_t *>(p_out);
}

void stats::register_fifo_stats(const std::string & name, fifo_stats *const fs)
{
	std::unique_lock<std::mutex> lck(lock);

	this->fs.insert({ name, fs });
}

std::string stats::to_json() const
{
	return stats_to_json(p, get_fifo_stats(), size);
}

std::vector<std::pair<const std::string, const fifo_stats *> > stats::get_fifo_stats() const
{
	std::vector<std::pair<const std::string, const fifo_stats *> > out;

	std::unique_lock<std::mutex> lck(lock);

	for(auto & item : fs)
		out.push_back({ item.first, item.second });

	return out;
}
