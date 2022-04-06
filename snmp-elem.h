// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

class snmp_elem
{
protected:
	uint8_t len { 255 };

public:
	snmp_elem();
	virtual ~snmp_elem();

	virtual uint8_t get_size() const { return len; }

	virtual std::pair<uint8_t *, uint8_t> get_payload() const;
};

//---

class snmp_integer : public snmp_elem
{
public:
	enum snmp_integer_type { si_counter32, si_integer, si_counter64, si_ticks };

private:
	snmp_integer_type type { si_integer };
	uint64_t          v    { 0 };

public:
	explicit snmp_integer(const snmp_integer_type type, const uint64_t v, const int len);
	explicit snmp_integer(const snmp_integer_type type, const uint64_t v);
	virtual ~snmp_integer();

	std::pair<uint8_t *, uint8_t> get_payload() const override;
};

//---

class snmp_sequence : public snmp_elem
{
protected:
	std::vector<const snmp_elem *> sequence;

public:
	snmp_sequence();
	virtual ~snmp_sequence();

	void add(const snmp_elem * const e);

	uint8_t get_size() const override;

	std::pair<uint8_t *, uint8_t> get_payload() const override;
};

//---

class snmp_null : public snmp_elem
{
public:
	snmp_null();
	virtual ~snmp_null();

	std::pair<uint8_t *, uint8_t> get_payload() const override;
};

//---

class snmp_octet_string : public snmp_elem
{
private:
	uint8_t *v { nullptr };

public:
	explicit snmp_octet_string(const uint8_t *const v, const int len);
	virtual ~snmp_octet_string();

	std::pair<uint8_t *, uint8_t> get_payload() const override;
};

//---

class snmp_oid : public snmp_elem
{
private:
	uint8_t *v { nullptr };

public:
	explicit snmp_oid(const std::string & oid);
	virtual ~snmp_oid();

	std::pair<uint8_t *, uint8_t> get_payload() const override;
};

//---

class snmp_pdu : public snmp_sequence
{
private:
	uint8_t type { 0x00 };

public:
	explicit snmp_pdu(const uint8_t type);
	virtual ~snmp_pdu();

	std::pair<uint8_t *, uint8_t> get_payload() const override;
};
