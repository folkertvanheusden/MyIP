// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <string>
#include <string.h>
#include <vector>

#include "any_addr.h"
#include "ax25.h"
#include "hash.h"
#include "str.h"
#include "utils.h"


any_addr::any_addr()
{
}

any_addr::any_addr(const addr_family af, const uint8_t src[])
{
	set(af, src);
}

any_addr::any_addr(const any_addr & other)
{
	other.get(addr, &addr_size);

	af = other.get_family();

	set_ = true;
}

any_addr::~any_addr()
{
}

uint16_t any_addr::get_word(const int nr) const
{
	assert(set_);
	assert(nr < addr_size - 1);  // !

	return (addr[nr] << 8) | addr[nr + 1];
}

bool any_addr::operator ==(const any_addr & other) const
{
	assert(set_);
	return compare_to(other);
}

bool any_addr::operator !=(const any_addr & other) const
{
	assert(set_);
	return !compare_to(other);
}

bool any_addr::compare_to(const any_addr & other) const
{
	assert(set_);

	if (other.get_family() != af)
		return false;

	uint8_t other_bytes[ANY_ADDR_SIZE] { 0 };
	int other_size { 0 };
	other.get(other_bytes, &other_size);

	bool rc = memcmp(other_bytes, addr, addr_size) == 0;

	return rc;
}

// for std::map::find
bool any_addr::operator () (const any_addr & lhs, const any_addr & rhs) const
{
	assert(set_);

	uint8_t lhs_bytes[ANY_ADDR_SIZE] { 0 };
	int lhs_size { 0 };
	lhs.get(lhs_bytes, &lhs_size);

	uint8_t rhs_bytes[ANY_ADDR_SIZE] { 0 };
	int rhs_size { 0 };
	rhs.get(rhs_bytes, &rhs_size);

	assert(lhs.get_family() == rhs.get_family());

	return memcmp(lhs_bytes, rhs_bytes, rhs_size) < 0;
}

bool any_addr::operator <(const any_addr & rhs) const
{
	assert(set_);

	if (get_family() != rhs.get_family())
		return get_family() < rhs.get_family();

	uint8_t rhs_bytes[ANY_ADDR_SIZE] { 0 };
	int rhs_size { 0 };
	rhs.get(rhs_bytes, &rhs_size);

	return memcmp(addr, rhs_bytes, rhs_size) < 0;
}

void any_addr::get(uint8_t *const tgt, int *tgt_size) const
{
	assert(set_);

	memcpy(tgt, addr, addr_size);

	*tgt_size = addr_size;
}

void any_addr::get(uint8_t *const tgt, int exp_size) const
{
	assert(set_);

	assert(exp_size == addr_size);

	memcpy(tgt, addr, exp_size);
}

void any_addr::set(const addr_family af_in, const uint8_t src[])
{
	int src_size = -1;

	if (af_in == mac)
		src_size = 6;
	else if (af_in == ipv4)
		src_size = 4;
	else if (af_in == ax25)
		src_size = 7;
	else if (af_in == ipv6)
		src_size = 16;

	memcpy(addr, src, src_size);
	addr_size = src_size;

	this->af = af_in;

	set_ = true;
}

std::string any_addr::to_str() const
{
	if (af == ipv4) {
		char buffer[16] { 0 };
		snprintf(buffer, sizeof buffer, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);

		return buffer;
	}

	if (af == mac) {
		char buffer[18] { 0 };
		snprintf(buffer, sizeof buffer, "%02x:%02x:%02x:%02x:%02x:%02x",
				addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

		return buffer;
	}

	if (af == ax25) {
		ax25_address aa(std::vector<uint8_t>(addr, addr + 7));

		return aa.to_str();
	}

	if (af == ipv6) {
		char buffer[40] { 0 };
		snprintf(buffer, sizeof buffer, "%x:%x:%x:%x:%x:%x:%x:%x",
				get_word(0), get_word(2), get_word(4), get_word(6), get_word(8),
				get_word(10), get_word(12), get_word(14));

		return buffer;
	}

	if (!set_)
		return "(not set)";

	assert(false);

	return "???";
}

const uint8_t & any_addr::operator[](const int index) const
{
	assert(set_);
	assert(index < addr_size);

	return addr[index];
}

uint64_t any_addr::get_hash() const
{
	assert(set_);

	return MurmurHash64A(addr, addr_size, 123);
}

// not useful, but to silence coverity
any_addr & any_addr::operator =(const any_addr && other)
{
	other.get(addr, &addr_size);

	af = other.get_family();

	set_ = true;

	return *this;
}

any_addr & any_addr::operator =(const any_addr & other)
{
	other.get(addr, &addr_size);

	af = other.get_family();

	set_ = true;

	return *this;
}

any_addr parse_address(const std::string & str, const size_t exp_size, const std::string & seperator, const int base)
{
	std::vector<std::string> parts = split(str, seperator);

	if (parts.size() != exp_size && !(exp_size == 16 && parts.size() == 8 /* ipv6 */))
		error_exit(false, "An address consists of %zu numbers", exp_size);

	any_addr::addr_family af { any_addr::mac };

	uint8_t *temp = new uint8_t[exp_size]();

	if (exp_size == 16) { // IPv6
		for(size_t i=0; i<exp_size; i += 2) {
			uint16_t val = strtol(parts.at(i / 2).c_str(), nullptr, base);

			temp[i + 0] = val >> 8;
			temp[i + 1] = val;
		}

		af = any_addr::ipv6;
	}
	else {
		for(size_t i=0; i<exp_size; i++)
			temp[i] = strtol(parts.at(i).c_str(), nullptr, base);

		af = exp_size == 4 ? any_addr::ipv4 : any_addr::mac;
	}

	any_addr rc = any_addr(af, temp);

	delete [] temp;

	return rc;
}
