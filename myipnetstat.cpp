#include <jansson.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "utils.h"


int main(int argc, char *argv[])
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1)
		error_exit(true, "Cannot create unix domain socket");

	struct sockaddr_un remote { 0 };

	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, "/tmp/myipstats.sock");

	int len = strlen(remote.sun_path) + sizeof(remote.sun_family);

	if (connect(fd, reinterpret_cast<sockaddr *>(&remote), len) == -1)
		error_exit(true, "Failed to connect");

	char cmd[] = "sessions\n";

	WRITE(fd, reinterpret_cast<const uint8_t *>(cmd), sizeof(cmd) - 1);

	for(;;) {
		char buffer[4096] { 0 };

		int rc = read(fd, buffer, (sizeof buffer) - 1);

		if (rc == 0 || rc == -1)
			break;

		printf("%s\n", buffer);
	}

	close(fd);

	return 0;
}
