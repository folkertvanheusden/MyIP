#include <stdint.h>
#include <string>

#include <openssl/md5.h>

#include "str.h"


std::string md5hex(const std::string & in)
{
	unsigned char result[MD5_DIGEST_LENGTH];

	MD5((unsigned char *)in.c_str(), in.size(), result);

	std::string rc;
	for(int i=0; i<MD5_DIGEST_LENGTH; i++)
		rc += myformat("%02x", result[i]);

	return rc;
}

uint64_t MurmurHash64A(const void *const key, const int len, const uint64_t seed)
{
	const uint64_t m = 0xc6a4a7935bd1e995LLU;
	const int r = 47;

	uint64_t h = seed ^ (len * m);

	const uint64_t *data = (const uint64_t *)key;
	const uint64_t *end = (len >> 3) + data;

	while(data != end) {
		uint64_t k = *data++;

		k *= m;
		k ^= k >> r;
		k *= m;

		h ^= k;
		h *= m;
	}

	const uint8_t *data2 = (const uint8_t *)data;

	switch(len & 7) {
		case 7: h ^= (uint64_t)(data2[6]) << 48;
		case 6: h ^= (uint64_t)(data2[5]) << 40;
		case 5: h ^= (uint64_t)(data2[4]) << 32;
		case 4: h ^= (uint64_t)(data2[3]) << 24;
		case 3: h ^= (uint64_t)(data2[2]) << 16;
		case 2: h ^= (uint64_t)(data2[1]) << 8;
		case 1: h ^= (uint64_t)(data2[0]);
			h *= m;
	};

	h ^= h >> r;
	h *= m;
	h ^= h >> r;

	return h;
}

uint32_t crc32(const uint8_t *const data, const size_t n_data, const uint32_t polynomial)
{
	const uint32_t p[] = { 0, polynomial };

	uint32_t crc = 0xFFFFFFFF;

	for(size_t i=0; i<n_data; i++) {
		uint8_t ch = data[i];

		for(size_t j=0; j<8; j++) {
			bool b = (ch ^ crc) & 1;

			crc >>= 1;

			crc ^= p[b];

			ch >>= 1;
		}
	}

	return ~crc;
}
