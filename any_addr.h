// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <stdint.h>
#include <string>


#define ANY_ADDR_SIZE 16

class any_addr {
public:
	enum addr_family { ipv4, mac, ax25, ipv6 };

private:
	addr_family af              { mac   };

	uint8_t addr[ANY_ADDR_SIZE] { 0     };  // fits IPv4 & 6
	int     addr_size           { 0     };
	bool    set_                { false };

	uint16_t get_word(const int nr) const;

public:
	any_addr();
	any_addr(const addr_family af, const uint8_t src[]);
	any_addr(const any_addr & org);
	virtual ~any_addr();

	bool is_set() const { return set_; }

	any_addr & operator =(const any_addr && other);
	any_addr & operator =(const any_addr & other);
	bool operator ==(const any_addr & other) const;
	bool operator !=(const any_addr & other) const;
	bool compare_to(const any_addr & other) const;
	bool operator () (const any_addr & lhs, const any_addr & rhs) const;  // for std::map::find
	bool operator <(const any_addr & rhs) const;  // for std::map::find

	void get(uint8_t *const tgt, int *tgt_size) const;
	void get(uint8_t *const tgt, int exp_size) const;
	const uint8_t & operator[](const int index) const;

	addr_family get_family() const { return af; }

	int get_len() const { return addr_size; }

	uint64_t get_hash() const;

	void set(const addr_family af, const uint8_t src[]);

	std::string to_str() const;
};

any_addr parse_address(const std::string & str, const size_t exp_size, const std::string & seperator, const int base);
