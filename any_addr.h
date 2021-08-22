// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <stdint.h>
#include <string>

#define ANY_ADDR_SIZE 16

class any_addr {
private:
	uint8_t addr[ANY_ADDR_SIZE] { 0 };  // fits IPv4 & 6
	int addr_size { 0 };

	uint16_t get_word(const int nr) const;

public:
	any_addr();
	any_addr(const uint8_t src[], const int src_size);
	any_addr(const any_addr & org);
	virtual ~any_addr();

	bool is_set() const { return !!addr_size; }

	any_addr & operator =(const any_addr & other);
	bool operator ==(const any_addr & other) const;
	bool operator !=(const any_addr & other) const;
	bool compare_to(const any_addr & other) const;
	bool operator () (const any_addr & lhs, const any_addr & rhs) const;  // for std::map::find
	bool operator <(const any_addr & rhs) const;  // for std::map::find

	void get(uint8_t *const tgt, int *tgt_size) const;
	void get(uint8_t *const tgt, int exp_size) const;
	const uint8_t & operator[](const int index) const;

	uint64_t get_hash() const;

	void set(const uint8_t src[], const int src_size);

	std::string to_str() const;
};

any_addr parse_address(const char *str, const size_t exp_size, const std::string & seperator, const int base);
