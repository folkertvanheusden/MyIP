// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "stats.h"
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

stats::stats(const int size) : size(size)
{
	fd = shm_open(shm_name, O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		perror("shm_open");
		exit(1);
	}

	if (ftruncate(fd, size) == -1) {
		perror("ftruncate");
		exit(1);
	}

	p = (uint8_t *)mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	close(fd);
}

stats::~stats()
{
	dolog("Removing shared memory segment");
	munmap(p, size);

	shm_unlink(shm_name);
}

uint64_t * stats::register_stat(const std::string & name)
{
	if (len + 32 > size)
		return nullptr;

	uint8_t *p_out = (uint8_t *)&p[len];

	// hopefully this platform allows atomic updates
	// not using locking, for speed
	*(uint64_t *)p_out = 0;

	int copy_n = std::min(name.size(), size_t(23));
	memcpy(&p_out[8], name.c_str(), copy_n);
	p_out[8 + copy_n] = 0x00;

	len += 32;

	return (uint64_t *)p_out;
}
