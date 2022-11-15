#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "log.h"


void swap_mac(uint8_t *a, uint8_t *b)
{
	uint8_t temp[6];
	memcpy(temp, a, 6);
	memcpy(a, b, 6);
	memcpy(b, temp, 6);
}

void swap_ipv4(uint8_t *a, uint8_t *b)
{
	uint8_t temp[4];
	memcpy(temp, a, 4);
	memcpy(a, b, 4);
	memcpy(b, temp, 4);
}

int create_datagram_socket(const int port)
{
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd == -1)
                return -1;

        struct sockaddr_in a { 0 };
        a.sin_family      = PF_INET;
        a.sin_port        = htons(port);
        a.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(fd, reinterpret_cast<const struct sockaddr *>(&a), sizeof(a)) == -1) {
                close(fd);

                DOLOG(ll_error, "Cannot bind to port %d: %s\n", port, strerror(errno));

                return -1;
        }

        return fd;
}

std::optional<std::string> get_host_as_text(struct sockaddr *const a)
{
	char buffer[INET6_ADDRSTRLEN > INET_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN] { 0 };

	if (a->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr_in6 = reinterpret_cast<struct sockaddr_in6 *>(a);

		if (!inet_ntop(a->sa_family, &addr_in6->sin6_addr, buffer, INET6_ADDRSTRLEN)) {
			DOLOG(info, "Problem converting sockaddr: %s\n", strerror(errno));

			return { };
		}
	}
	else if (a->sa_family == AF_INET) {
		struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(a);

		if (!inet_ntop(a->sa_family, &addr_in->sin_addr, buffer, INET_ADDRSTRLEN)) {
			DOLOG(info, "Problem converting sockaddr: %s\n", strerror(errno));

			return { };
		}
	}
	else {
		DOLOG(warning, "Unsupported address family %d\n", a->sa_family);

		return { };
	}

	return buffer;
}
