#pragma once

#include <atomic>
#include <functional>

#include "buffer_in.h"
#include "packet.h"
#include "pstream.h"
#include "session.h"
#include "types.h"


typedef struct {
	std::function<void()> init;
	std::function<bool(pstream *const ps, session *const s)> new_session;
	std::function<bool(pstream *const ps, session *const s, buffer_in data)> new_data;
	std::function<bool(pstream *const ps, session *const s)> session_closed_1;  // please terminate
	std::function<bool(pstream *const ps, session *const s)> session_closed_2;  // should be terminated, clean up
	std::function<void()> deinit;
	private_data *pd;
} port_handler_t;


class application
{
protected:
	std::atomic_bool stop_flag { false   };
	private_data    *const pd  { nullptr };

public:
	application() {
	}

	virtual ~application() {
		ask_to_stop();
	}

	void ask_to_stop() {
		stop_flag = true;
	}
};
