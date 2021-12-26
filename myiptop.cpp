// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <fcntl.h>
#include <ncurses.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "utils.h"
#include "stats-utils.h"

constexpr char shm_name[] = "/myip";
constexpr int size = 8192;

void help()
{
	printf("-j   json output (one-shot)\n");
	printf("-c x display output x times and then exit (not for json)\n");
	printf("-n   ncurses ui\n");
}

int main(int argc, char *argv[])
{
	int count = -1;
	bool json = false, nc = false;
	int c = 0;
	while((c = getopt(argc, argv, "jc:nh")) != -1) {
		if (c == 'j')
			json = true;
		else if (c == 'c')
			count = atoi(optarg);
		else if (c == 'n')
			nc = true;
		else if (c == 'h') {
			help();
			return 0;
		}
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
		std::vector<std::pair<const std::string, const fifo_stats *> > dummy;

		std::string out = stats_to_json(p, dummy, sb.st_size);

		printf("%s\n", out.c_str());
	}
	else if (nc) {
		WINDOW *w = initscr();

		int maxx = 0, maxy = 0;
		getmaxyx(w, maxy, maxx);

		int cnt = 0;

		for(;count == -1 || cnt++ < count;) {
			werase(w);

			uint8_t *const p_end = &p[sb.st_size];
			uint8_t *cur_p = p;

			int nr = 1;

			time_t t = time(nullptr);
			struct tm tm;
			localtime_r(&t, &tm);

			mvwprintw(w, 0, 0, "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);

			while(cur_p < p_end && cur_p[16]) {
				uint64_t *cnt_p = (uint64_t *)cur_p;
				uint64_t *cnt_p2 = (uint64_t *)(cur_p + 8);

				if (nr & 1)
					wattron(w, A_BOLD);

				mvwprintw(w, nr % maxy, (nr / maxy) * 38, "%s\n", &cur_p[16]);

				if (*cnt_p2)
					mvwprintw(w, nr % maxy, (nr / maxy) * 38 + 29, "%.2f\n", *cnt_p / double(*cnt_p2));
				else
					mvwprintw(w, nr % maxy, (nr / maxy) * 38 + 29, "%lu\n", *cnt_p);

				if (nr & 1)
					wattroff(w, A_BOLD);

				cur_p += 48;
				nr++;
			}

			wmove(w, 0, 37);

			wrefresh(w);
			doupdate();

			sleep(1);
		}

		endwin();
	}
	else {
		int nr = 0;

		for(;count == -1 || nr++ < count;) {
			printf("\n");

			uint8_t *const p_end = &p[sb.st_size];
			uint8_t *cur_p = p;

			while(cur_p < p_end && cur_p[16]) {
				uint64_t *cnt_p = (uint64_t *)cur_p;
				uint64_t *cnt_p2 = (uint64_t *)(cur_p + 8);

				if (*cnt_p2)
					printf("%s\t%.2f\n", &cur_p[16], *cnt_p / double(*cnt_p2));
				else
					printf("%s\t%lu\n", &cur_p[16], *cnt_p);

				cur_p += 48;
			}

			if (nr < count || count == -1)
				sleep(1);
		}
	}

	munmap(p, size);

	close(fd);
}
