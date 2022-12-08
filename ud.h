#include <atomic>
#include <thread>
#include <vector>

#include "tcp.h"


class ud_stats
{
private:
	int                    fd              { -1      };
	std::vector<pstream *> stream_session_handlers;

        std::thread           *th              { nullptr };
        std::atomic_bool       stop_flag       { false   };

	void handler(const int cfd);
	void emit_sessions(const int cfd);

public:
	ud_stats(const std::vector<pstream *> & stream_session_handlers, const std::string & socket_path);
	virtual ~ud_stats();

	void operator()();
};
