#include <atomic>
#include <poll.h>
#include <string.h>
#include <thread>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "error.h"
#include "socks_proxy.h"
#include "utils.h"

ssize_t READ(int fd, uint8_t *whereto, size_t len)
{
	ssize_t cnt=0;

	while(len > 0)
	{
		ssize_t rc = read(fd, whereto, len);

		if (rc == -1)
		{
			if (errno == EINTR || errno == EAGAIN) {
				DOLOG(debug, "EINTR/EAGAIN %d", errno);
				continue;
			}

			return -1;
		}
		else if (rc == 0)
			break;
		else
		{
			whereto += rc;
			len -= rc;
			cnt += rc;
		}
	}

	return cnt;
}

ssize_t WRITE(int fd, const uint8_t *whereto, size_t len)
{
	ssize_t cnt=0;

	while(len > 0)
	{
		ssize_t rc = write(fd, whereto, len);

		if (rc == -1)
		{
			if (errno == EINTR || errno == EAGAIN) {
				DOLOG(debug, "EINTR/EAGAIN %d", errno);
				continue;
			}

			return -1;
		}
		else if (rc == 0)
			return -1;
		else
		{
			whereto += rc;
			len -= rc;
			cnt += rc;
		}
	}

	return cnt;
}

void set_no_delay(const int fd, const bool use_no_delay)
{
        int flag = use_no_delay;

        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int)) == -1)
                error_exit(true, "could not set TCP_NODELAY on socket");
}

int start_listen(const char *const adapter, const int port, const int q_size, const bool use_tcp_fastopen)
{
	struct sockaddr_in6 server6_addr { 0 };
	size_t server6_addr_len = sizeof server6_addr;

	struct sockaddr_in server_addr { 0 };
	size_t server_addr_len = sizeof server_addr;

	bool is_ipv6 = true;

	server6_addr.sin6_port = htons(port);

	if (strcmp(adapter, "0.0.0.0") == 0 || strcmp(adapter, "::1") == 0) {
		server6_addr.sin6_addr = in6addr_any;
		server6_addr.sin6_family = AF_INET6;
	}
	else {
		if (inet_pton(AF_INET6, adapter, &server6_addr.sin6_addr) == 0) {
			if (inet_pton(AF_INET, adapter, &server_addr.sin_addr) == 0)
				error_exit(false, "inet_pton(%s) failed", adapter);
			else {
				server_addr.sin_family = AF_INET;
				server_addr.sin_port = htons(port);
				is_ipv6 = false;
			}
		}
		else {
			server6_addr.sin6_family = AF_INET6;
		}
	}

	int fd = socket(is_ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		error_exit(true, "failed creating socket");

	int reuse_addr = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse_addr, sizeof(reuse_addr)) == -1)
		error_exit(true, "setsockopt(SO_REUSEADDR) failed");

	if (use_tcp_fastopen) {
		if (setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &q_size, sizeof q_size))
			error_exit(true, "Failed to enable TCP FastOpen");
	}

	if (bind(fd, is_ipv6 ? (struct sockaddr *)&server6_addr : (struct sockaddr *)&server_addr, is_ipv6 ? server6_addr_len : server_addr_len) == -1)
		error_exit(true, "bind(%s.%d) failed", adapter, port);

	if (listen(fd, q_size) == -1)
		error_exit(true, "listen(%d) failed", q_size);

	return fd;
}

socks_proxy::socks_proxy(const std::string & interface, const int port, tcp *const t) : t(t)
{
	fd = start_listen(interface.c_str(), port, SOMAXCONN, true);

	th = new std::thread(std::ref(*this));
}

socks_proxy::~socks_proxy()
{
	close(fd);

	stop_flag = true;

	th->join();
	delete th;
}

bool socks_new_data(tcp_session_t *ts, const packet *pkt, const uint8_t *data, size_t data_len, private_data *pd)
{
	int fd = dynamic_cast<socks_private_data *>(pd)->get_fd();

	dolog(debug, "socks_new_data for fd %d (%s)\n", fd, std::string((const char *)data, data_len).c_str());

	return WRITE(fd, data, data_len) == ssize_t(data_len);
}

void socks_session_closed_2(tcp_session_t *ts, private_data *pd)
{
	int fd = dynamic_cast<socks_private_data *>(pd)->get_fd();

	dolog(debug, "socks_session_closed_2 for fd %d\n", fd);

	close(fd);
}

static void socks_handler(const int fd, tcp *const t)
{
	DOLOG(debug, "socks_handler: handler started\n");

	// get client request
	uint8_t header[8];
	if (READ(fd, header, sizeof header) != sizeof header) {
		close(fd);
		DOLOG(debug, "socks_handler: short read\n");
		return;
	}

	if (header[0] != 4) {  // must be socks 4
		close(fd);
		DOLOG(debug, "socks_handler: not version 4\n");
		return;
	}

	if (header[1] != 1) {  // connect
		close(fd);
		DOLOG(debug, "socks_handler: not \"connect\"\n");
		return;
	}

	int port = (header[2] << 8) | header[3];
	any_addr dest(&header[4], 4);

	// id
	for(;;) {
		uint8_t buffer = 0;

		if (READ(fd, &buffer, 1) != 1) {
			close(fd);
			DOLOG(debug, "socks_handler: problem receiving id\n");
			break;
		}

		if (buffer == 0x00)
			break;
	}

	// send response
	uint8_t response[8] { 0, 0x5a, uint8_t(port >> 8), uint8_t(port), 0 };
	if (WRITE(fd, response, sizeof response) != sizeof response) {
		close(fd);
		DOLOG(debug, "socks_handler: problem sending response\n");
		return;
	}

	socks_private_data spd(fd);

	DOLOG(debug, "socks_handler: allocate client session\n");
	int src_port = t->allocate_client_session(socks_new_data, socks_session_closed_2, dest, port, &spd);

	DOLOG(debug, "socks_handler: client session allocated, local port: %d, fd: %d\n", src_port, fd);

	for(;;) {
		uint8_t buffer[512];
		int n = read(fd, buffer, sizeof buffer);

		if (n == 0) {
			DOLOG(debug, "socks_handler: closed\n");
			break;
		}

		if (n == -1) {
			DOLOG(debug, "socks_handler: error (%s)\n", strerror(errno));
			break;
		}

		dolog(debug, "%s\n", std::string((char *)buffer, n).c_str());

		t->client_session_send_data(src_port, buffer, n);
	}

	t->close_client_session(src_port);

	close(fd);

	DOLOG(debug, "socks_handler: end\n");
}

void socks_proxy::operator()()
{
	struct pollfd fds[] = { { fd, POLLIN, 0 } };

	while(!stop_flag) {
                if (poll(fds, 1, 500) <= 0)
                        continue;

                int cfd = accept(fd, nullptr, nullptr);
		if (cfd == -1) {
			DOLOG(info, "accept for socks-proxy failed\n");
			continue;
		}

		std::thread *th = new std::thread(socks_handler, cfd, t);
		// TODO
	}
}
