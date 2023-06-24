#include <atomic>
#include <thread>
#include <vector>

#include "tcp.h"


class ud_stats
{
private:
	int                    fd              { -1      };
	std::vector<pstream *> stream_session_handlers;

	std::vector<phys *>   *const devs      { nullptr };

        std::thread           *th              { nullptr };
        std::atomic_bool       stop_flag       { false   };

	void handler      (const int cfd);

	void emit_devices (const int cfd);
	void emit_sessions(const int cfd);

	void handle_pcap  (const int cfd, const std::string & dev, const bool open);

	void emit_arp     (const int cfd, const std::string & dev_name);

public:
	ud_stats(const std::vector<pstream *> & stream_session_handlers, std::vector<phys *> *const devs, const std::string & socket_path);
	virtual ~ud_stats();

	void operator()();
};
