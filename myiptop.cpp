// (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <fcntl.h>
#include <map>
#include <ncurses.h>
#include <poll.h>
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

void ncurses_ui(const uint8_t *const p, const uint8_t *const p_end)
{
	initscr();
        cbreak();
        intrflush(stdscr, FALSE);
        noecho();
        nonl();
        refresh();
        meta(stdscr, TRUE);
        idlok(stdscr, TRUE);
        idcok(stdscr, TRUE);
        leaveok(stdscr, FALSE);
        keypad(stdscr, TRUE);

	int maxx = 0, maxy = 0;
	getmaxyx(stdscr, maxy, maxx);

	WINDOW *win_names = newwin(maxy, 16, 0, 0);
	WINDOW *win_values = newwin(maxy, maxx - 18, 0, 18);

	std::map<std::string, std::map<std::string, uint64_t *> > values;

	const uint8_t *cur_p = p;
	while(cur_p < p_end && cur_p[16]) {
		std::string name = (char *)&cur_p[16];
		std::size_t underscore = name.find('_');
		std::string prefix = name.substr(0, underscore);

		auto it = values.find(prefix);
		if (it == values.end()) {
			std::map<std::string, uint64_t *> new_pair;
		       	new_pair.insert({ name, (uint64_t *)&cur_p[0] });

			values.insert({ prefix, new_pair });
		}
		else {
			it->second.insert({ name, (uint64_t *)&cur_p[0] });
		}

		cur_p += 48;
	}

	int cursor = 0;

	struct pollfd fds[] { { 0, POLLIN, 0 } };

	for(;;) {
		int nr = 0;

		werase(win_names);
		werase(win_values);

		time_t t = time(nullptr);
		struct tm tm { 0 };
		localtime_r(&t, &tm);
		mvwprintw(win_names, 0, 0, "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);

		for(auto & it : values) {
			mvwprintw(win_names, nr + 1, 1, "%c%s", nr == cursor ? '>' : ' ', it.first.c_str());

			if (nr == cursor) {
				int nr2 = 0;

				for(auto & it_entries : it.second) {
					mvwprintw(win_values, nr2 % maxy, (nr2 / maxy) * 38, "%s", it_entries.first.c_str());

					uint64_t *cnt_p = it_entries.second;
					uint64_t *cnt_p2 = &cnt_p[1];

					if (*cnt_p2)
						mvwprintw(win_values, nr2 % maxy, (nr2 / maxy) * 38 + 29, "%.2f", *cnt_p / double(*cnt_p2));
					else
						mvwprintw(win_values, nr2 % maxy, (nr2 / maxy) * 38 + 29, "%lu", *cnt_p);

					nr2++;
				}
			}

			nr++;
		}

		wrefresh(win_names);
		wrefresh(win_values);
		wmove(win_names, cursor + 1, 0);
		doupdate();

		if (poll(fds, 1, 500)) {
			int c = getch();

			if (c == KEY_UP && cursor > 0)
				cursor--;
			else if (c == KEY_DOWN && cursor < values.size() - 1)
				cursor++;
			else if (c == 'q')
				break;
		}
	}

	endwin();
}

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
	else if (nc)
		ncurses_ui(p, &p[sb.st_size]);
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
