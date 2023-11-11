// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once

#include <atomic>
#include <map>
#include <optional>
#include <stdint.h>
#include <string>
#include <vector>

#include "any_addr.h"
#include "buffer_in.h"
#include "network_layer.h"
#include "phys.h"
#include "router.h"
#include "stats.h"


class ipv4;

class ax25_address
{
private:
	bool        valid    { false };
	std::string address;
	char        ssid     { '0'   };
	bool        end_mark { false };
	bool        repeated { false };

public:
	ax25_address();

	ax25_address(const std::vector<uint8_t> & from);

	ax25_address(const any_addr & a);

	ax25_address(const ax25_address & a);

	ax25_address(const std::string & a, const char ssid, const bool end_mark, const bool repeated);

	ax25_address(const std::string & a, const bool end_mark, const bool repeated);

	ax25_address & operator=(const ax25_address &);

	bool get_valid()    const { return valid;    }

	bool get_end_mark() const { return end_mark; }

	bool get_repeated() const { return repeated; }

	std::string get_address() const { return address;  }

	char        get_ssid() const    { return ssid;     }

	void set_address(const std::string & address, const char ssid);

	std::pair<uint8_t *, size_t> generate_address() const;

	any_addr    get_any_addr() const;
};

class ax25_packet
{
public:
	enum frame_type { TYPE_I, TYPE_S, TYPE_U };

private:
	bool                      valid    { false };
	ax25_address              from;
	ax25_address              to;
	std::vector<ax25_address> seen_by;
	uint8_t                   control  { 0     };
	frame_type                type     { TYPE_I };
	std::optional<uint8_t>    msg_nr   {       };
	std::optional<uint8_t>    pid      {       };
	buffer_in                 data;

public:
	ax25_packet();
	ax25_packet(const std::vector<uint8_t> & in);
	~ax25_packet();

	void set_from   (const std::string & callsign, const char ssid, const bool end_mark, const bool repeated);
	void set_from   (const any_addr & callsign);
	void set_to     (const std::string & callsign, const char ssid, const bool end_mark, const bool repeated);
	void set_to     (const any_addr & callsign);
	void set_control(const uint8_t control);
	void set_pid    (const uint8_t pid    );
	void set_type   (const frame_type f   );
	void set_data   (const uint8_t *const p, const size_t size);

	ax25_address get_from() const;
	ax25_address get_to  () const;
	std::vector<ax25_address> get_seen_by() const;
	buffer_in    get_data() const;
	std::optional<uint8_t> get_pid () const;
	bool         get_valid() const { return valid; }
	frame_type   get_type() const  { return type;  }

	std::pair<uint8_t *, size_t> generate_packet() const;

	std::string  to_str() const;
};
