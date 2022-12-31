#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "log.h"


int open_tty(const std::string & dev_name, const int bps)
{
	int fd = open(dev_name.c_str(), O_RDWR);

	if (fd == -1) {
		DOLOG(ll_error, "open %s: %s", dev_name.c_str(), strerror(errno));
		exit(1);
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		DOLOG(ll_error, "fcntl(FD_CLOEXEC): %s", strerror(errno));
		exit(1);
	}

        struct termios tty;
        if (tcgetattr(fd, &tty) != 0) {
		DOLOG(ll_error, "tcgetattr on %s: %s\n", dev_name.c_str(), strerror(errno));
		exit(1);
        }

        cfsetospeed(&tty, bps);
        cfsetispeed(&tty, bps);

        tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;     // 8-bit chars
        tty.c_iflag &= ~IGNBRK;         // disable break processing
        tty.c_lflag = 0;                // no signaling chars, no echo,
                                        // no canonical processing
        tty.c_oflag = 0;                // no remapping, no delays
        tty.c_cc[VMIN]  = 1;            // read blocks
        tty.c_cc[VTIME] = 127;            // 12.7 seconds read timeout

        tty.c_iflag &= ~(IXON | IXOFF | IXANY); // disable xon/xoff ctrl

        tty.c_cflag |= (CLOCAL | CREAD);// ignore modem controls,
                                        // enable reading
        tty.c_cflag &= ~(PARENB | PARODD);      // shut off parity
        tty.c_cflag &= ~CSTOPB;
        tty.c_cflag &= ~CRTSCTS;

        if (tcsetattr(fd, TCSANOW, &tty) != 0) {
		DOLOG(ll_error, "tcsetattr on %s: %s\n", dev_name.c_str(), strerror(errno));
		exit(1);
        }

	return fd;
}
