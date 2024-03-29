// (C) 2022-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <assert.h>
#include <chrono>
#include <stdint.h>
#include <string>
#include <string.h>
#include <arpa/inet.h>

#include "ax25.h"
#include "log.h"
#include "phys.h"
#include "router.h"
#include "str.h"
#include "time.h"
#include "utils.h"


const std::map<uint8_t, std::string> pid_names = {
	{ 0x10, "AX.25 layer 3 implemented" },
	{ 0x20, "AX.25 layer 3 implemented" },
	{ 0x01, "ISO 8208/CCiTT X.25 PLP" },
	{ 0x06, "Compressed TCP/IP packet. Van Jacobson (RFC 1144)" },
	{ 0x07, "Uncompressed TCP/IP packet. Van Jacobson (RFC 1144)" },
	{ 0x08, "Segmentation fragment" },
	{ 0xC3, "TEXNET datagram protocol" },
	{ 0xC4, "Link Quality Protocol" },
	{ 0xCA, "Appletalk" },
	{ 0xCB, "Appletalk ARP" },
	{ 0xCC, "ARPA Internet Protocol" },
	{ 0xCD, "ARPA Address resolution" },
	{ 0xCE, "FlexNet" },
	{ 0xCF, "Net/ROM" },
	{ 0xF0, "No layer 3 protocol implemented" },
	{ 0xFF, "Escape character. Next octet contains more Level 3 protocol" },
};

ax25_address::ax25_address()
{
}

ax25_address::ax25_address(const std::vector<uint8_t> & from)
{
	if (from.size() < 7) {
		invalid_reason = myformat("address too short %zu < 7 ", from.size());
		return;
	}

	bool end = false;

	for(int i=0; i<6; i++) {
		uint8_t b = from[i];

		if ((b & 1) && i != 5) {  // why not in byte 5?
			invalid_reason = myformat("byte %d has lsb set (%s)", i, bin_to_text(from.data(), 6, false).c_str());
			return;
		}

		char    c = char(b >> 1);

		if (c == 0 || c == 32 || end)
			end = true;
		else
			address += c;
	}

	end_mark = from[6] & 1;
	repeated = (from[6] & 128) == 128;
	ssid     = (from[6] >> 1) & 0x0f;

	valid    = true;
}

ax25_address::ax25_address(const any_addr & from)
{
	bool end = false;

	for(int i=0; i<6; i++) {
		uint8_t b = from[i];

		if (b & 1)
			return;

		char    c = char(b >> 1);

		if (c == 0 || c == 32 || end)
			end = true;
		else
			address += c;
	}

	end_mark = from[6] & 1;

	repeated = !!(from[6] & 128);

	ssid = (from[6] >> 1) & 0x0f;

	valid = true;
}

ax25_address::ax25_address(const ax25_address & a)
{
	valid    = a.get_valid   ();
	invalid_reason = a.get_invalid_reason();

	address  = a.get_address ();
	ssid     = a.get_ssid    ();

	end_mark = a.get_end_mark();
	repeated = a.get_repeated();
}

ax25_address::ax25_address(const std::string & a, const int ssid, const bool end_mark, const bool repeated)
{
	this->address  = a;
	this->ssid     = ssid;

	this->end_mark = end_mark;
	this->repeated = repeated;

	this->valid    = true;
}

ax25_address::ax25_address(const std::string & a, const bool end_mark, const bool repeated)
{
	std::size_t dash = a.find("-");

	if (dash != std::string::npos) {
		this->address = a.substr(0, dash);
		this->ssid    = a[dash + 1];
	}
	else {
		this->address = a;
		this->ssid    = 0;
	}

	this->end_mark = end_mark;
	this->repeated = repeated;

	this->valid    = true;
}

ax25_address & ax25_address::operator=(const ax25_address & in)
{
	address  = in.get_address();
	ssid     = in.get_ssid();

	end_mark = in.get_end_mark();
	repeated = in.get_repeated();

	valid    = in.get_valid();
	invalid_reason = in.get_invalid_reason();

	return *this;
}

bool ax25_address::operator==(const ax25_address & other) const
{
	if (other.get_valid() != valid)
		return false;

	if (other.get_address() != address)
		return false;

	if (other.get_ssid() != ssid)
		return false;

	return true;
}

void ax25_address::set_address(const std::string & address, const int ssid)
{
	this->address = address;
	this->ssid    = ssid;
}

std::vector<uint8_t> ax25_address::generate_address() const
{
	std::vector<uint8_t> out(7);

	size_t put_n = std::min(size_t(6), address.size());

	for(size_t i=0; i<std::min(size_t(6), address.size()); i++)
		out[i] = address[i] << 1;

	for(size_t i=put_n; i<6; i++)
		out[i] = ' ' << 1;

	out[6] = (ssid << 1) | end_mark | (repeated ? 128 : 0);

	return out;
}

any_addr ax25_address::get_any_addr() const
{
	auto addr = generate_address();

	any_addr out(any_addr::ax25, addr.data());

	return out;
}

ax25_packet::ax25_packet()
{
}

ax25_packet::ax25_packet(const std::vector<uint8_t> & in)
{
	if (in.size() < 14) {
		invalid_reason = myformat("packet too short (%zu bytes)", in.size());
		return;
	}

	to     = ax25_address(std::vector<uint8_t>(in.begin() + 0, in.begin() + 7));

	if (!to.get_valid()) {
		invalid_reason = "to invalid: " + to.get_invalid_reason();
		return;
	}

	from   = ax25_address(std::vector<uint8_t>(in.begin() + 7, in.begin() + 14));

	if (!from.get_valid()) {
		invalid_reason = "from invalid: " + from.get_invalid_reason();
		return;
	}

	bool end_mark = from.get_end_mark();

	std::size_t offset = 14;

	for(int i=0; i<2 && end_mark == false; i++) {
		ax25_address a(std::vector<uint8_t>(in.begin() + offset, in.begin() + offset + 7));
		offset += 7;

		end_mark = a.get_end_mark();

		if (!a.get_valid()) {
			invalid_reason = "via invalid: " + a.get_invalid_reason();
			return;
		}

		repeaters.push_back(a);
	}

	control = in[offset++];
	if ((control & 1) == 0 || (control & 0xef) == 0x03) {
		pid = in[offset++];
		type = (control & 0xef) == 0x03 ? TYPE_UI : TYPE_I;
	}
	else {
		if (control & 2)
			type = TYPE_U;
		else
			type = TYPE_S;
	}

	if (offset < in.size())
		data = buffer_in(in.data() + offset, in.size() - offset);

	valid = true;
}

ax25_packet::~ax25_packet()
{
}

ax25_address ax25_packet::get_from() const
{
	return from;
}

ax25_address ax25_packet::get_to() const
{
	return to;
}

std::vector<ax25_address> ax25_packet::get_repeaters() const
{
	return repeaters;
}

void ax25_packet::add_repeater(const any_addr & addr)
{
	ax25_address temp(addr);

	for(auto & repeater : repeaters) {
		if (repeater == temp)
			return;
	}

	repeaters.push_back(temp);
}

buffer_in ax25_packet::get_data() const
{
	return data;
}

void ax25_packet::set_from(const std::string & callsign, const int ssid, const bool end_mark, const bool repeated)
{
	from = ax25_address(callsign, ssid, end_mark, repeated);
}

void ax25_packet::set_from(const any_addr & callsign)
{
	from = ax25_address(callsign);
}

void ax25_packet::set_to(const std::string & callsign, const int ssid, const bool end_mark, const bool repeated)
{
	to   = ax25_address(callsign, ssid, end_mark, repeated);
}

void ax25_packet::set_to(const any_addr & callsign)
{
	to   = ax25_address(callsign);
}

void ax25_packet::set_data(const uint8_t *const p, const size_t size)
{
	data = buffer_in(p, size);
}

void ax25_packet::set_control(const uint8_t control)
{
	this->control = control;
}

void ax25_packet::set_type(const frame_type f)
{
	if (f == TYPE_I)
		control &= 254;
	else {
		control |= 1;

		if (f == TYPE_S)
			control &= ~2;
		else
			control |= 2;
	}
}

void ax25_packet::set_pid(const uint8_t pid)
{
	this->pid = pid;
}

std::optional<uint8_t> ax25_packet::get_pid() const
{
	return pid;
}

std::pair<uint8_t *, size_t> ax25_packet::generate_packet() const
{
	int      data_size = data.get_size();

	uint8_t *out       = reinterpret_cast<uint8_t *>(calloc(1, data_size + 1024 /* more than enough for an ax.25 header */));

	auto addr_to       = to.generate_address();
	memcpy(&out[0], addr_to.data(), 7);

	auto copy_from     = from;
	if (repeaters.empty() == false)
		copy_from.reset_end_mark();
	auto addr_from     = copy_from.generate_address();
	memcpy(&out[7], addr_from.data(), 7);

	int offset = 14;

	for(size_t i=0; i<repeaters.size(); i++) {
		auto copy_repeater = repeaters.at(i);

		if (i != repeaters.size() - 1)
			copy_repeater.reset_end_mark();
		else
			copy_repeater.set_end_mark();

		auto addr_repeater = copy_repeater.generate_address();
		memcpy(&out[offset], addr_repeater.data(), 7);
		offset += 7;
	}

	out[offset++] = control;
	if ((control & 1) == 0 || (control & 0xef) == 0x03)  // I or UI
		out[offset++] = pid.has_value() ? pid.value() : 0;

	memcpy(&out[offset], data.get_bytes(data_size), data_size);

	return { out, data_size + offset };
}

std::string ax25_packet::to_str() const
{
	std::string repeaters_str;

	for(auto & repeater : repeaters) {
		if (repeaters_str.empty() == false)
			repeaters_str += " / ";
		else
			repeaters_str += ", repeaters:";

		repeaters_str += repeater.to_str();
	}

	std::string pid_str;
	if (type == ax25_packet::TYPE_I && pid.has_value()) {
		auto it = pid_names.find(pid.value());

		if (it != pid_names.end())
			pid_str = ", PID: " + it->second;
	}

	return myformat("valid:%d, from:%s, to:%s%s control:%02x%s", valid, from.to_str().c_str(), to.to_str().c_str(), repeaters_str.c_str(), control, pid_str.c_str());
}
