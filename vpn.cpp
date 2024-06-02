// (C) 2024 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/des.h>
#include <sys/time.h>

#include "hash.h"
#include "log.h"
#include "phys_vpn_insertion_point.h"
#include "vpn.h"
#include "str.h"
#include "time.h"
#include "udp.h"
#include "utils.h"


// NOTE: this is a very weak encrypted vpn
// do not use it for anything important or even at all!
vpn::vpn(phys_vpn_insertion_point *const phys, stats *const s, udp *const u, const any_addr & my_ip, const int my_port, const any_addr & peer_ip, const int peer_port, const std::string & psk):
	phys(phys),
	u(u),
	my_ip(my_ip),
	my_port(my_port),
	peer_ip(peer_ip),
	peer_port(peer_port)
{
	vpn_recv = s->register_stat("vpn_recv", "1.3.6.1.4.1.57850.1.15.1");
	vpn_send = s->register_stat("vpn_send", "1.3.6.1.4.1.57850.1.15.2");

	DES_string_to_key(psk.c_str(), &key);

	int rc = DES_set_key_checked(&key, &sched_encrypt);
	if (rc == -1)
		CDOLOG(ll_warning, "[vpn]", "Key: bad parity\n");
	else if (rc == -2)
		CDOLOG(ll_warning, "[vpn]", "Key is weak\n");

	DES_set_key_checked(&key, &sched_decrypt);
}

vpn::~vpn()
{
}

void vpn::input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, packet *p, session_data *const pd)
{
	DOLOG(ll_debug, "VPN: packet from %s:%d to %s:%d\n", src_ip.to_str().c_str(), src_port, dst_ip.to_str().c_str(), dst_port);

	auto pl = p->get_payload();
	if (pl.second & 7) {  // must be multiple of 8 due to DES
		DOLOG(ll_debug, "VPN: size (%d) is not multiple of 8\n", pl.second);
		return;
	}

	uint8_t *temp = new uint8_t[pl.second]();

        // decrypt
	for(size_t o=0; o<pl.second; o += 8) {
		uint8_t input[8] { };
		DES_ncbc_encrypt(&pl.first[o], &temp[o], 8, &sched_decrypt, &ivec_decrypt, DES_DECRYPT);
	}

	// validate md5
	uint8_t md5_compare[MD5_DIGEST_LENGTH] { };
        md5bin(&temp[MD5_DIGEST_LENGTH], pl.second - MD5_DIGEST_LENGTH, md5_compare);

	if (memcmp(md5_compare, temp, MD5_DIGEST_LENGTH) == 0) {
		size_t   o          = MD5_DIGEST_LENGTH;
		uint16_t ether_type = (temp[o + 0] << 8) | temp[o + 1];
		uint16_t pl_size    = (temp[o + 2] << 8) | temp[o + 3];
		o += 4;

		any_addr::addr_family dst_family = any_addr::addr_family(temp[o++]);
		uint8_t  dst_len    = temp[o++];
		any_addr dst_mac(dst_family, &temp[o]);
		o += dst_len;

		any_addr::addr_family src_family = any_addr::addr_family(temp[o++]);
		uint8_t  src_len    = temp[o++];
		any_addr src_mac(src_family, &temp[o]);
		o += src_len;

		CDOLOG(ll_debug, "[vpn]", "VPN: %s -> %s\n", src_mac.to_str().c_str(), dst_mac.to_str().c_str());

		if (phys->insert_packet(dst_mac, src_mac, ether_type, temp, pl_size))
			CDOLOG(ll_debug, "[vpn]", "VPN: packet input fail\n");
	}
	else {
		CDOLOG(ll_debug, "[vpn]", "VPN: hash mismatch\n");
	}

	delete [] temp;
}

void vpn::operator()()
{
	set_thread_name("myip-vpn");
}

bool vpn::transmit_packet(const any_addr & dst_mac, const any_addr & src_mac, const uint16_t ether_type, const uint8_t *const payload, const size_t pl_size)
{
        // real crypto would pad the packet so that an attacker has no
        // idea of the size which gives hints about its contents
        size_t   out_len = MD5_DIGEST_LENGTH + 2 + 2 + 1 + dst_mac.get_len() + 1 + src_mac.get_len() + pl_size;
	if (out_len & 7)
		out_len += 8 - (out_len & 7);
        uint8_t *out     = new uint8_t[out_len]();

        // payload
	size_t   o = MD5_DIGEST_LENGTH;
	// meta
        out[o++] = ether_type >> 8;
        out[o++] = ether_type;
        out[o++] = pl_size >> 8;
        out[o++] = pl_size;
	// addresses
	out[o++] = dst_mac.get_family();
	int temp = 0;
	out[o++] = dst_mac.get_len();
	dst_mac.get(&out[o], &temp);
	o += temp;

	out[o++] = src_mac.get_family();
	out[o++] = src_mac.get_len();
	src_mac.get(&out[o], &temp);
	o += temp;
	// data
        if (pl_size)
                memcpy(&out[o], payload, pl_size);

        // add hash
	// real crypto would not use md5
        md5bin(&out[MD5_DIGEST_LENGTH], out_len - MD5_DIGEST_LENGTH, out);

        // encrypt
	for(size_t o=0; o<out_len; o += 8) {
		uint8_t input[8] { };
		memcpy(input, &out[o], 8);

		DES_ncbc_encrypt(input, &out[o], 8, &sched_encrypt, &ivec_encrypt, DES_ENCRYPT);
	}

	CDOLOG(ll_debug, "[VPN]", "Packet %s->%s to peer (%zu to %zu bytes)\n", src_mac.to_str().c_str(), dst_mac.to_str().c_str(), pl_size, out_len);

	if (u->transmit_packet(peer_ip, peer_port, my_ip, my_port, out, out_len) == false) {
		CDOLOG(ll_debug, "[vpn]", "VPN: packet transmit fail\n");
		delete [] out;
		return false;
	}

	delete [] out;

	return true;
}
