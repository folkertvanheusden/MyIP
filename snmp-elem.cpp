#include <cassert>
#include <cstring>

#include "snmp-elem.h"

snmp_elem::snmp_elem()
{
}

snmp_elem::~snmp_elem()
{
}

std::pair<uint8_t *, uint8_t> snmp_elem::get_payload() const
{
	return { nullptr, 0 };
}

//---

snmp_integer::snmp_integer(const uint64_t v, const int len) : v(v)
{
	this->len = len;
}

snmp_integer::snmp_integer(const uint64_t v)
{
	if (v <= 0xffffffff)
		this->v = v, len = 4;
	else
		this->v = v, len = 8;
}

snmp_integer::~snmp_integer()
{
}

std::pair<uint8_t *, uint8_t> snmp_integer::get_payload() const
{
	uint8_t size = len + 2;
	uint8_t *out = (uint8_t *)malloc(size);

	out[0] = 0x02;
	out[1] = len;

	for(int i=0; i<len; i++)
		out[i + 2] = v >> (len * 8 - (i + 1) * 8);

	return { out, size };
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
	sequence.push_back(e);
}

uint8_t snmp_sequence::get_size() const
{
	uint8_t t = 0;

	for(auto e : sequence)
		t += e->get_size();

	t += sequence.size() * 2;

	return t;
}

std::pair<uint8_t *, uint8_t> snmp_sequence::get_payload() const
{
	uint8_t out_size = get_size() + 2;
	uint8_t *out = (uint8_t *)malloc(out_size);

	out[0] = 0x30;
	out[1] = out_size - 2;

	uint8_t o = 2;

	for(auto e : sequence) {
		auto pl = e->get_payload();

		memcpy(&out[o], pl.first, pl.second);

		o += pl.second;

		free(pl.first);
	}

	assert(o == out_size);

	return { out, out_size };
}

//---

snmp_null::snmp_null()
{
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
	this->len = len;
}

snmp_octet_string::~snmp_octet_string()
{
	free(v);
}

std::pair<uint8_t *, uint8_t> snmp_octet_string::get_payload() const
{
	uint8_t out_len = len + 2;
	uint8_t *out = (uint8_t *)malloc(out_len);
	memcpy(out + 2, v, len);

	out[0] = 0x04;
	out[1] = len;

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

	uint8_t temp[(8 * 9) / 7];
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

	len = p - v;
}

snmp_oid::~snmp_oid()
{
	free(v);
}

std::pair<uint8_t *, uint8_t> snmp_oid::get_payload() const
{
	uint8_t out_len = len + 2;
	uint8_t *out = (uint8_t *)malloc(out_len);
	memcpy(out + 2, v, len);

	out[0] = 0x06;
	out[1] = len;

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
