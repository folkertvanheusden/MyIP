// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <stdint.h>
#include <string>
#include <thread>
#include <vector>

#include "any_addr.h"
#include "application.h"
#include "snmp-data.h"
#include "stats.h"

class packet;
class udp;

typedef struct _oid_req_t_ {
	std::vector<std::string> oids;
	uint64_t req_id { 0 };
	int err { 0 }, err_idx { 0 };

	int version { 0 };
	std::string community;

	_oid_req_t_() {
	}
} oid_req_t;

class snmp : public application
{
private:
	snmp_data *const sd;
	stats     *const s;
	udp       *const u;

	uint64_t running_since { 0 }; // ms

	uint64_t *snmp_requests { nullptr }, *snmp_invalid { nullptr };

	bool process_BER(const uint8_t *p, const size_t len, oid_req_t *const oids_req, const bool is_getnext, const int is_top);
	uint64_t get_INTEGER(const uint8_t *p, const size_t len);
	bool get_OID(const uint8_t *p, const size_t length, std::string *const oid_out);
	bool get_type_length(const uint8_t *p, const size_t len, uint8_t *const type, uint8_t *const length);
	bool process_PDU(const uint8_t*, const size_t, oid_req_t *const oids_req, const bool is_getnext);

	void add_oid(uint8_t **const packet_out, size_t *const output_size, const std::string & oid);
	void add_octet_string(uint8_t **const packet_out, size_t *const output_size, const char *const str);
	void gen_reply(oid_req_t & oids_req, uint8_t **const packet_out, size_t *const output_size);

public:
	snmp(snmp_data *const sd, stats *const s, udp *const u);
	snmp(const snmp &) = delete;
	virtual ~snmp();

	void input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, session_data *const pd);
};
