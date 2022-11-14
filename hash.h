
#include <stdint.h>
#include <string>


uint64_t MurmurHash64A(const void *const key, const int len, const uint64_t seed);
std::string md5hex(const std::string & in);

uint32_t crc32(const uint8_t *const data, const size_t n_data, const uint32_t polynomial);
