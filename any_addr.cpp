// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <string>
#include <string.h>
#include <vector>

#include "any_addr.h"
#include "utils.h"

any_addr::any_addr()
{
}

any_addr::any_addr(const uint8_t src[], const int src_size)
{
	set(src, src_size);
}

any_addr::any_addr(const any_addr & other)
{
	other.get(addr, &addr_size);
}

any_addr::~any_addr()
{
}

uint16_t any_addr::get_word(const int nr) const
{
	assert(nr < addr_size - 1);  // !

	return (addr[nr] << 8) | addr[nr + 1];
}

bool any_addr::operator ==(const any_addr & other) const
{
	return compare_to(other);
}

bool any_addr::operator !=(const any_addr & other) const
{
	return !compare_to(other);
}

bool any_addr::compare_to(const any_addr & other) const
{
	uint8_t other_bytes[ANY_ADDR_SIZE] { 0 };
	int other_size { 0 };
	other.get(other_bytes, &other_size);

	if (other_size != addr_size)
		return false;

	bool rc = memcmp(other_bytes, addr, addr_size) == 0;

	return rc;
}

// for std::map::find
bool any_addr::operator () (const any_addr & lhs, const any_addr & rhs) const
{
	uint8_t lhs_bytes[ANY_ADDR_SIZE] { 0 };
	int lhs_size { 0 };
	lhs.get(lhs_bytes, &lhs_size);

	uint8_t rhs_bytes[ANY_ADDR_SIZE] { 0 };
	int rhs_size { 0 };
	rhs.get(rhs_bytes, &rhs_size);

	assert(lhs_size == rhs_size);

	return memcmp(lhs_bytes, rhs_bytes, rhs_size) < 0;
}

bool any_addr::operator <(const any_addr & rhs) const
{
	uint8_t rhs_bytes[ANY_ADDR_SIZE] { 0 };
	int rhs_size { 0 };
	rhs.get(rhs_bytes, &rhs_size);

	assert(addr_size == rhs_size);

	return memcmp(addr, rhs_bytes, rhs_size) < 0;
}

void any_addr::get(uint8_t *const tgt, int *tgt_size) const
{
	memcpy(tgt, addr, addr_size);

	*tgt_size = addr_size;
}

void any_addr::get(uint8_t *const tgt, int exp_size) const
{
	assert(exp_size == addr_size);

	memcpy(tgt, addr, exp_size);
}

void any_addr::set(const uint8_t src[], const int src_size)
{
	assert(src_size <= 16);

	memcpy(addr, src, src_size);
	addr_size = src_size;
}

std::string any_addr::to_str() const
{
	if (addr_size == 4) {  // assume IPv4
		char buffer[16];
		snprintf(buffer, sizeof buffer, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);

		return buffer;
	}

	if (addr_size == 6) {  // assume MAC address
		char buffer[18];
		snprintf(buffer, sizeof buffer, "%02x:%02x:%02x:%02x:%02x:%02x",
				addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

		return buffer;
	}

	if (addr_size == 16) {  // assume IPv6
		char buffer[40];
		snprintf(buffer, sizeof buffer, "%x:%x:%x:%x:%x:%x:%x:%x",
				get_word(0), get_word(2), get_word(4), get_word(6), get_word(8),
				get_word(10), get_word(12), get_word(14));

		return buffer;
	}

	assert(false);

	return "???";
}

const uint8_t & any_addr::operator[](const int index) const
{
	assert(index < addr_size);

	return addr[index];
}

uint64_t any_addr::get_hash() const
{
	return std::hash<std::string>{}(to_str());
}

// not useful, but to silence coverity
any_addr & any_addr::operator =(const any_addr && other)
{
	other.get(addr, &addr_size);

	return *this;
}

any_addr & any_addr::operator =(const any_addr & other)
{
	other.get(addr, &addr_size);

	return *this;
}

any_addr parse_address(const char *str, const size_t exp_size, const std::string & seperator, const int base)
{
	std::vector<std::string> *parts = split(str, seperator);

	if (parts->size() != exp_size && !(exp_size == 16 && parts->size() == 8 /* ipv6 */)) {
		fprintf(stderr, "An address consists of %zu numbers\n", exp_size);
		exit(1);
	}

	uint8_t *temp = new uint8_t[exp_size];

	if (exp_size == 16) { // IPv6
		for(size_t i=0; i<exp_size; i += 2) {
			uint16_t val = strtol(parts->at(i / 2).c_str(), nullptr, base);

			temp[i + 0] = val >> 8;
			temp[i + 1] = val;
		}
	}
	else {
		for(size_t i=0; i<exp_size; i++)
			temp[i] = strtol(parts->at(i).c_str(), nullptr, base);
	}

	any_addr rc = any_addr(temp, exp_size);

	delete [] temp;

	delete parts;

	return rc;
}
