#include <atomic>
#include <jansson.h>
#include <poll.h>
#include <thread>
#include <vector>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>

#include "ud.h"
#include "utils.h"


ud_stats::ud_stats(const std::vector<pstream *> & stream_session_handlers, const std::string & socket_path) :
	stream_session_handlers(stream_session_handlers)
{
	fd = socket(AF_UNIX, SOCK_STREAM, 0);

	unlink(socket_path.c_str());

	sockaddr_un local { 0 };

	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, socket_path.c_str());

	int len = strlen(local.sun_path) + sizeof(local.sun_family);
	if (bind(fd, reinterpret_cast<sockaddr *>(&local), len) == -1)
		error_exit(true, "UD: bind() failed");

	if (listen(fd, SOMAXCONN) == -1)
		error_exit(true, "UD: listen() failed");

	th = new std::thread(std::ref(*this));
}

ud_stats::~ud_stats()
{
	stop_flag = true;

	close(fd);

	th->join();
	delete th;
}

void ud_stats::emit_sessions(const int cfd)
{
	json_t *out = json_array();

	for(auto & stream : stream_session_handlers) {
		auto sessions = stream->get_sessions_locked();

		for(auto & session : *sessions) {
			json_t *record = json_object();

			json_object_set(record, "their-addr", json_string(session.second->get_their_addr().to_str().c_str()));
			json_object_set(record, "my-addr", json_string(session.second->get_my_addr().to_str().c_str()));

			json_object_set(record, "their-port", json_integer(session.second->get_their_port()));
			json_object_set(record, "my-port", json_integer(session.second->get_my_port()));

			json_object_set(record, "session-hash", json_integer(session.second->get_hash()));

			json_object_set(record, "terminating", json_integer(session.second->get_is_terminating()));

			json_object_set(record, "state-name", json_string(session.second->get_state_name().c_str()));

			auto ts = session.second->get_session_creation_time();

			json_object_set(record, "created-at", json_integer(ts.tv_sec * 1000000ll + ts.tv_nsec / 1000));

			json_array_append(out, record);
		}

		stream->sessions_unlock();
	}

	char *temp = json_dumps(out, 0);

	WRITE(cfd, reinterpret_cast<uint8_t *>(temp), strlen(temp));

	free(temp);

	json_decref(out);
}

void ud_stats::handler(const int cfd)
{
	std::string cmd;

	for(;;) {
		char buffer[16] { 0 };

		if (read(cfd, reinterpret_cast<uint8_t *>(buffer), 15) <= 0)
			return;

		cmd += buffer;

		std::size_t lf = cmd.find('\n');
		if (lf != std::string::npos) {
			cmd = cmd.substr(0, lf);
			break;
		}
	}

	if (cmd == "sessions")
		emit_sessions(cfd);

	close(cfd);
}

void ud_stats::operator()()
{
	set_thread_name("ud_stats");

	std::vector<std::pair<std::thread *, int> > clients;

	pollfd fds[] = { { fd, POLLIN, 0 } };

	while(!stop_flag) {
		sockaddr_un remote { 0 };
		socklen_t   sl     { 0 };

		int rc = poll(fds, 1, 100);
		if (rc == 0)
			continue;

		if (rc == -1) {
			DOLOG(ll_info, "poll on unix domain socket failed: %s\n", strerror(errno));
			break;
		}

		int cfd = accept(fd, reinterpret_cast<sockaddr *>(&remote), &sl);
		if (cfd == -1)
			continue;

		clients.push_back({ new std::thread([&] { handler(cfd); }), cfd });

		for(size_t i=0; i<clients.size();) {
			if (clients.at(i).first->joinable()) {
				clients.at(i).first->join();

				delete clients.at(i).first;

				clients.erase(clients.begin() + i);
			}
			else {
				i++;
			}
		}
	}

	for(auto & th : clients) {
		close(th.second);

		th.first->join();

		delete th.first;
	}
}
