// (C) 2020 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "utils.h"

constexpr char shm_name[] = "/myip";
constexpr int size = 4096;

int main(int argc, char *argv[])
{
	bool json = false;
	int c = 0;
	while((c = getopt(argc, argv, "-j")) != -1) {
		if (c == 'j')
			json = true;
	}

	int fd = shm_open(shm_name, O_RDONLY, 0444);
	if (fd == -1) {
		perror("shm_open");
		exit(1);
	}

	struct stat sb;
	if (fstat(fd, &sb) == -1) {
		perror("fstat");
		exit(1);
	}

	uint8_t *const p = (uint8_t *)mmap(nullptr, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	if (json) {
		std::string out;

		uint8_t *const p_end = &p[sb.st_size];
		uint8_t *cur_p = p;

		while(cur_p < p_end && cur_p[8]) {
			uint64_t *cnt_p = (uint64_t *)cur_p;

			if (out.empty())
				out = "{ ";
			else
				out += ", ";

			out += myformat("\"%s\" : ", &cur_p[8]);
			out += myformat("%lu", *cnt_p);

			cur_p += 32;
		}

		out += " }";

		dolog("%s\n", out.c_str());
	}
	else {
		for(;;) {
			dolog("\n");

			uint8_t *const p_end = &p[sb.st_size];
			uint8_t *cur_p = p;

			while(cur_p < p_end && cur_p[8]) {
				uint64_t *cnt_p = (uint64_t *)cur_p;

				dolog("%s\t%lu\n", &cur_p[8], *cnt_p);

				cur_p += 32;
			}

			sleep(1);
		}
	}

	munmap(p, size);

	close(fd);
}
