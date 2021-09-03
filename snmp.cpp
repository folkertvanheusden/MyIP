// (C) 2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "snmp.h"
#include "snmp-elem.h"
#include "udp.h"
#include "utils.h"


snmp::snmp(stats *const s, udp *const u) : s(s), u(u)
{
	snmp_requests = s->register_stat("snmp_requests");
	snmp_invalid  = s->register_stat("snmp_invalid");
}

snmp::~snmp()
{
}

uint64_t snmp::get_INTEGER(const uint8_t *p, const size_t length)
{
	uint64_t v = 0;

	if (length > 8)
		dolog(info, "SNMP: INTEGER truncated (%zu bytes)", length);

	for(size_t i=0; i<length; i++) {
		v <<= 8;
		v |= *p++;
	}

	return v;
}

bool snmp::get_type_length(const uint8_t *p, const size_t len, uint8_t *const type, uint8_t *const length)
{
	if (len < 2)
		return false;

	*type = *p++;

	*length = *p++;

	return true;
}

bool snmp::get_OID(const uint8_t *p, const size_t length, std::string *const oid_out)
{
	oid_out->clear();

	uint32_t v = 0;

	for(size_t i=0; i<length; i++) {
		if (p[i] < 128) {
			v <<= 7;
			v |= p[i];

			if (i == 0 && v == 43)
				*oid_out += "1.3";
			else
				*oid_out += myformat(".%d", v);

			v = 0;
		}
		else {
			v <<= 7;
			v |= p[i] & 127;
		}
	}

	if (v) {
		dolog(warning, "SNMP: object identifier did not properly terminate\n");
		return false;
	}

	return true;
}

bool snmp::process_PDU(const uint8_t *p, const size_t len, oid_req_t *const oids_req, const bool is_getnext)
{
	uint8_t pdu_type = 0, pdu_length = 0;

	// ID
	if (!get_type_length(p, len, &pdu_type, &pdu_length))
		return false;

	if (pdu_type != 0x02) // expecting an integer here)
		return false;

	p += 2;

	oids_req->req_id = get_INTEGER(p, pdu_length);
	p += pdu_length;

	// error
	if (!get_type_length(p, len, &pdu_type, &pdu_length))
		return false;

	if (pdu_type != 0x02) // expecting an integer here)
		return false;

	p += 2;

	uint64_t error = get_INTEGER(p, pdu_length);
	(void)error;
	p += pdu_length;

	// error index
	if (!get_type_length(p, len, &pdu_type, &pdu_length))
		return false;

	if (pdu_type != 0x02) // expecting an integer here)
		return false;

	p += 2;

	uint64_t error_index = get_INTEGER(p, pdu_length);
	(void)error_index;
	p += pdu_length;

	// varbind list sequence
	uint8_t type_vb_list = *p++;
	if (type_vb_list != 0x30)
		return false;
	uint8_t len_vb_list = *p++;

	const uint8_t *pnt = p;

	while(pnt < &p[len_vb_list]) {
		uint8_t seq_type = *pnt++;
		uint8_t seq_length = *pnt++;

		if (&pnt[seq_length] > &p[len_vb_list]) {
			dolog(warning, "SNMP: length field out of bounds\n");
			return false;
		}

		if (seq_type == 0x30) {  // sequence
			process_BER(pnt, seq_length, oids_req, is_getnext, 0);
			pnt += seq_length;
		}
		else {
			dolog(warning, "SNMP: unexpected/invalid type %02x\n", seq_type);
			return false;
		}
	}

	return true;
}

bool snmp::process_BER(const uint8_t *p, const size_t len, oid_req_t *const oids_req, const bool is_getnext, const int is_top)
{
	const uint8_t *pnt = p;
	bool first_integer = true;
	bool first_octet_str = true;

	while(pnt < &p[len]) {
		uint8_t type = *pnt++;
		uint8_t length = *pnt++;

		if (&pnt[length] > &p[len]) {
			dolog(warning, "SNMP: length field out of bounds\n");
			return false;
		}

		if (type == 0x02) {  // integer
			if (is_top && first_integer)
				oids_req->version = get_INTEGER(pnt, length);

			first_integer = false;

			pnt += length;
		}
		else if (type == 0x04) {  // octet string
			std::string v((const char *)pnt, length);

			if (is_top && first_octet_str)
				oids_req->community = v;

			first_octet_str = false;

			pnt += length;
		}
		else if (type == 0x05) {  // null
			// ignore for now
			pnt += length;
		}
		else if (type == 0x06) {  // object identifier
			std::string oid_out;

			if (!get_OID(pnt, length, &oid_out))
				return false;

			if (is_getnext) {
				std::string oid_next = s->find_next_oid(oid_out);

				if (oid_next.empty()) {
					oids_req->err = 2;
					oids_req->err_idx = 1;
				}
				else {
					oids_req->oids.push_back(oid_next);
				}
			}
			else {
				oids_req->oids.push_back(oid_out);
			}

			pnt += length;
		}
		else if (type == 0x30) {  // sequence
			if (!process_BER(pnt, length, oids_req, is_getnext, is_top - 1))
				return false;

			pnt += length;
		}
		else if (type == 0xa0) {  // GetRequest PDU
			if (!process_PDU(pnt, length, oids_req, is_getnext))
				return false;
			pnt += length;
		}
		else if (type == 0xa1) {  // GetNextRequest PDU
			if (!process_PDU(pnt, length, oids_req, true))
				return false;
			pnt += length;
		}
		else if (type == 0xa3) {  // SetRequest PDU
			if (!process_PDU(pnt, length, oids_req, is_getnext))
				return false;
			pnt += length;
		}
		else {
			dolog(warning, "SNMP: invalid type %02x\n", type);
			return false;
		}
	}

	return true;
}

void snmp::gen_reply(oid_req_t & oids_req, uint8_t **const packet_out, size_t *const output_size)
{
	snmp_sequence *se = new snmp_sequence();

	se->add(new snmp_integer(oids_req.version));  // version

	std::string community = oids_req.community;
	if (community.empty())
		community = "public";

	se->add(new snmp_octet_string((const uint8_t *)community.c_str(), community.size()));  // community string

	// request pdu
	snmp_pdu *GetResponsePDU = new snmp_pdu(0xa2);
	se->add(GetResponsePDU);

	GetResponsePDU->add(new snmp_integer(oids_req.req_id));  // ID

	GetResponsePDU->add(new snmp_integer(oids_req.err));  // error

	GetResponsePDU->add(new snmp_integer(oids_req.err_idx));  // error index

	snmp_sequence *varbind_list = new snmp_sequence();
	GetResponsePDU->add(varbind_list);

	for(auto e : oids_req.oids) {
		snmp_sequence *varbind = new snmp_sequence();
		varbind_list->add(varbind);

		varbind->add(new snmp_oid(e));

		uint64_t *vp = s->find_by_oid(e);

		if (vp) {
			dolog(debug, "SNMP: requested %s gives %lu\n", e.c_str(), *vp);

			varbind->add(new snmp_integer(*vp));
		}
		else {  // FIXME snmp_null?
			dolog(debug, "SNMP: requested %s not found, returning 0\n", e.c_str());

			varbind->add(new snmp_integer(0));
		}
	}

	auto rc = se->get_payload();
	*packet_out = rc.first;
	*output_size = rc.second;

	delete se;
}

void snmp::input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, void *const pd)
{
	stats_inc_counter(snmp_requests);

	dolog(debug, "SNMP: request from [%s]:%d\n", src_ip.to_str().c_str(), src_port);

        auto pl = p->get_payload();

        if (pl.second == 0) {
		stats_inc_counter(snmp_invalid);
                dolog(info, "SNMP: empty packet from [%s]:%u\n", src_ip.to_str().c_str(), src_port);
                return;
        }

	oid_req_t or_;

	if (!process_BER(pl.first, pl.second, &or_, false, 2)) {
                dolog(info, "SNMP: failed processing request\n");
		stats_inc_counter(snmp_invalid);
                return;
	}

	uint8_t *packet_out = nullptr;
	size_t output_size = 0;

	gen_reply(or_, &packet_out, &output_size);

	if (output_size) {
		dolog(debug, "SNMP: sending reply of %zu bytes to [%s]:%d\n", output_size, src_ip.to_str().c_str(), src_port);
		u->transmit_packet(src_ip, src_port, dst_ip, dst_port, packet_out, output_size);

		free(packet_out);
	}
}
