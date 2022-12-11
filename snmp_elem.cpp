// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <cassert>
#include <cstring>

#include "log.h"
#include "snmp_elem.h"

snmp_elem::snmp_elem()
{
}

snmp_elem::~snmp_elem()
{
}

std::pair<uint8_t *, uint8_t> snmp_elem::get_payload() const
{
	DOLOG(ll_info, "SNMP_elem::get_payload invoked\n");
	return { nullptr, 0 };
}

//---

snmp_integer::snmp_integer(const snmp_integer_type type, const uint64_t v, const int len) :
	type(type),
	v(v)
{
	this->len = len + 2;
}

snmp_integer::snmp_integer(const snmp_integer_type type, const uint64_t v) :
	type(type)
{
	if (v <= 0xffffffff)
		this->v = v, len = 4 + 2;
	else
		this->v = v, len = 8 + 2;
}

snmp_integer::~snmp_integer()
{
}

std::pair<uint8_t *, uint8_t> snmp_integer::get_payload() const
{
	uint8_t snmp_type = 0x00;

	if (type == si_integer)
		snmp_type = 0x02;
	else if (type == si_counter32)
		snmp_type = 0x41;  // COUNTER32
	else if (type == si_counter64)
		snmp_type = 0x46;  // COUNTER64
	else if (type == si_ticks)
		snmp_type = 0x43;  // TIME_TICKS
	else
		assert(0);

	uint8_t pl_len = len - 2;
	uint8_t *out = (uint8_t *)malloc(len);

	out[0] = snmp_type;
	out[1] = pl_len;

	for(int i=0; i<pl_len; i++)
		out[i + 2] = v >> (pl_len * 8 - (i + 1) * 8);

	return { out, len };
}

//---

snmp_sequence::snmp_sequence()
{
}

snmp_sequence::~snmp_sequence()
{
	for(auto e : sequence)
		delete e;
}

void snmp_sequence::add(const snmp_elem * const e)
{
	assert(e);

	sequence.push_back(e);
}

uint8_t snmp_sequence::get_size() const
{
	auto pl = get_payload();

	free(pl.first);

	return pl.second;
}

std::pair<uint8_t *, uint8_t> snmp_sequence::get_payload() const
{
	uint8_t *out = (uint8_t *)malloc(256);

	out[0] = 0x30;

	uint8_t o = 2;

	for(auto e : sequence) {
		auto pl = e->get_payload();

		if (o + pl.second > 256) {
			DOLOG(ll_info, "SNMP_sequence::get_payload type %02x (%d bytes) won't fit\n", pl.first[0], pl.second);
			break;
		}

		memcpy(&out[o], pl.first, pl.second);

		o += pl.second;

		free(pl.first);
	}

	out[1] = o - 2;

	return { out, o };
}

//---

snmp_null::snmp_null()
{
	len = 0;
}

snmp_null::~snmp_null()
{
}

std::pair<uint8_t *, uint8_t> snmp_null::get_payload() const
{
	uint8_t *out = (uint8_t *)malloc(2);

	out[0] = 0x05;
	out[1] = 0x00;

	return { out, 2 };
}

//---

snmp_octet_string::snmp_octet_string(const uint8_t *const v, const int len)
{
	this->v = (uint8_t *)malloc(len);
	memcpy(this->v, v, len);
	this->len = len + 2;
}

snmp_octet_string::~snmp_octet_string()
{
	free(v);
}

std::pair<uint8_t *, uint8_t> snmp_octet_string::get_payload() const
{
	uint8_t out_len = len;
	uint8_t pl_len = len - 2;
	uint8_t *out = (uint8_t *)malloc(out_len);

	memcpy(out + 2, v, pl_len);

	out[0] = 0x04;
	out[1] = pl_len;

	return { out, out_len };
}

//---

snmp_oid::snmp_oid(const std::string & oid)
{
	int new_size = oid.size();

	uint8_t *p = v = (uint8_t *)malloc(new_size);

	std::string work = oid;

	if (work.substr(0, 4) == "1.3.") {
		*p++ = 43;
		work = work.substr(4);
	}

	uint8_t temp[(8 * 9) / 7] { 0 };
	int temp_o = 0;

	while(work.empty() == false) {
		uint64_t v = atoll(work.c_str());

		// put
		if (v == 0) {
			temp[0] = 0;
			temp_o = 1;
		}
		else {
			while(v) {
				temp[temp_o++] = v & 127;
				v >>= 7;
			}
		}

		while(temp_o) {
			temp_o--;
			*p++ = temp[temp_o] | (temp_o == 0 ? 0 : 128);
		}

		std::size_t dot = work.find('.');
		if (dot == std::string::npos)
			break;

		work = work.substr(dot + 1);
	}

	len = p - v + 2;
}

snmp_oid::~snmp_oid()
{
	free(v);
}

std::pair<uint8_t *, uint8_t> snmp_oid::get_payload() const
{
	uint8_t out_len = len;
	uint8_t pl_len = len - 2;
	uint8_t *out = (uint8_t *)malloc(out_len);

	if (pl_len)
		memcpy(out + 2, v, pl_len);

	out[0] = 0x06;
	out[1] = pl_len;

	return { out, out_len };
}

//---

snmp_pdu::snmp_pdu(const uint8_t type) : type(type)
{
}

snmp_pdu::~snmp_pdu()
{
}

std::pair<uint8_t *, uint8_t> snmp_pdu::get_payload() const
{
	auto out = snmp_sequence::get_payload();

	out.first[0] = type;

	return out;
}
