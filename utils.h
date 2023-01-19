// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <optional>
#include <stdint.h>
#include <string>
#include <vector>

uint8_t *duplicate(const uint8_t *const in, const size_t size);

void get_random(uint8_t *tgt, size_t n);

uint8_t * get_from_buffer(uint8_t **p, size_t *len, size_t get_len);

void set_thread_name(std::string name);
bool file_exists(const std::string & file, size_t *const file_size = nullptr);
void run(const std::string & what);

void error_exit(const bool se, const char *format, ...);

std::optional<std::string> load_text_file(const std::string & filename);

ssize_t READ(int fd, uint8_t *whereto, size_t len);
ssize_t WRITE(int fd, const uint8_t *wherefrom, size_t len);

int determine_value_size(uint32_t n);
