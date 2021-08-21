// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under AGPL v3.0
#pragma once
#include <stdint.h>
#include <string>
#include <vector>

void swap_mac(uint8_t *a, uint8_t *b);
void swap_ipv4(uint8_t *a, uint8_t *b);
uint8_t *duplicate(const uint8_t *const in, const size_t size);
std::string myformat(const char *const fmt, ...);
uint64_t get_us();
void get_random(uint8_t *tgt, size_t n);
std::vector<std::string> * split(std::string in, std::string splitter);
uint8_t * get_from_buffer(uint8_t **p, size_t *len, size_t get_len);
void dolog(const char *fmt, ...);
void set_thread_name(const std::string & name);
std::string bin_to_text(const uint8_t *p, const size_t len);
bool file_exists(const std::string & file, size_t *const file_size = nullptr);
