// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <algorithm>
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
	dolog(debug, "Removing shared memory segment\n");
	munmap(p, size);

	shm_unlink(shm_name);
}

void walk_tree(const std::map<std::string, oid_t> & tree, const std::string & parent)
{
	for(auto k : tree) {
		std::string child = parent + "." + k.first;

		fprintf(stderr, " \"%s\" [shape=circle];\n", child.c_str());

		fprintf(stderr, " \"%s\" -> \"%s\";\n", parent.c_str(), child.c_str());

		walk_tree(k.second.children, k.second.s.oid);
	}
}

void dump_tree(const std::map<std::string, oid_t> & tree)
{
	fprintf(stderr, "digraph test {\n");
	fprintf(stderr, " top [shape=circle];\n");
	walk_tree(tree, "top");
	fprintf(stderr, "}\n");
}

uint64_t * stats::register_stat(const std::string & name, const std::string & oid)
{
	if (len + 40 > size) {
		dolog(error, "stats: shm is full\n");
		return nullptr;
	}

	lock.lock();

	auto lut_it = lut.find(name);
	if (lut_it != lut.end()) {
		uint64_t *rc = lut_it->second.p;
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

	auto lut_rc = lut.insert(std::pair<std::string, stats_t>(name, st));
	assert(lut_rc.second);

	if (oid.empty() == false) {
		std::map<std::string, oid_t> *p_lut = &lut_oid;

		std::vector<std::string> *parts = split(oid, ".");

		std::string cur_oid;

		for(size_t i=0; i<parts->size(); i++) {
			auto it = p_lut->find(parts->at(i));

			if (cur_oid.empty() == false)
				cur_oid += ".";

			cur_oid += parts->at(i);

			if (it == p_lut->end()) {
				oid_t o;
				o.s.oid = cur_oid;
				o.index = atoi(parts->at(i).c_str());

				auto rc = p_lut->insert(std::pair<std::string, oid_t>(parts->at(i), o));

				it = rc.first;
			}

			if (i == parts->size() - 1) {
				it->second.s = st;
				it->second.index = atoi(parts->at(i).c_str());
			}
			else {
				p_lut = &it->second.children;
			}
		}

		delete parts;
	}

	lock.unlock();

	return (uint64_t *)p_out;
}

std::string stats::to_json() const
{
	return stats_to_json(p, size);
}

uint64_t * stats::find_by_oid(const std::string & oid)
{
	uint64_t *rc = nullptr;

	lock.lock();

	std::map<std::string, oid_t> *p_lut = &lut_oid;

	std::vector<std::string> *parts = split(oid, ".");

	for(size_t i=0; i<parts->size(); i++) {
		auto it = p_lut->find(parts->at(i));

		if (it == p_lut->end())
			break;

		if (i == parts->size() - 1)
			rc = it->second.s.p;
		else
			p_lut = &it->second.children;
	}

	delete parts;

	lock.unlock();

	return rc;
}

std::string get_sibling(std::map<std::string, oid_t> & m, const int who)
{
	if (m.empty())
		return "";

	struct int_cmp {
		bool operator()(const std::pair<std::string, oid_t> & lhs, const std::pair<std::string, oid_t> & rhs) {
			return lhs.second.index < rhs.second.index;
		}
	};

	std::vector<std::pair<std::string, oid_t> > temp(m.begin(), m.end());
	std::stable_sort(temp.begin(), temp.end(), int_cmp());

	for(size_t i=0; i<temp.size(); i++) {
		if (temp.at(i).second.index > who)
			return temp.at(i).second.s.oid;
	}

	return "";
}

std::string stats::find_next_oid(const std::string & oid)
{
	std::string out;

	lock.lock();

//	dump_tree(lut_oid);

	std::map<std::string, oid_t> *p_lut = &lut_oid;

	std::vector<std::string> *parts = split(oid, ".");

	for(size_t i=0; i<parts->size(); i++) {
		auto it = p_lut->find(parts->at(i));

		if (it == p_lut->end())
			break;

		if (i == parts->size() - 1) {
			out = get_sibling(*p_lut, atoi(parts->at(i).c_str()));

			if (out.empty() == true) {
				p_lut = &it->second.children;

				out = get_sibling(*p_lut, -1);
			}

			break;
		}

		p_lut = &it->second.children;
	}

	delete parts;

	lock.unlock();

	return out;
}
