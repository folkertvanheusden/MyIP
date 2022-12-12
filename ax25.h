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
private:
	bool                      valid    { false };
	ax25_address              from;
	ax25_address              to;
	std::vector<ax25_address> seen_by;
	uint8_t                   control  { 0     };
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
	void set_data   (const uint8_t *const p, const size_t size);

	ax25_address get_from() const;
	ax25_address get_to  () const;
	std::vector<ax25_address> get_seen_by() const;
	buffer_in    get_data() const;
	std::optional<uint8_t> get_pid () const;
	bool         get_valid() const { return valid; }

	std::pair<uint8_t *, size_t> generate_packet() const;
};


class ax25 : public network_layer
{
private:
	std::thread   *th { nullptr };

	// AX.25 callsign is mapped to a MAC
	const any_addr my_mac;

public:
	ax25(stats *const s, const any_addr & my_mac, router *const r);
	virtual ~ax25();

	any_addr get_addr() const override { return any_addr(); }

	bool transmit_packet(const std::optional<any_addr> & dst_mac, const any_addr & dst_ip, const any_addr & src_ip, const uint8_t protocol, const uint8_t *payload, const size_t pl_size, const uint8_t *const header_template) override;

	virtual int get_max_packet_size() const override { return 256; }

	void operator()() override;
};
