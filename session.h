#pragma once

#include <atomic>
#include <mutex>
#include <stdint.h>
#include <time.h>

#include "any_addr.h"
#include "str.h"
#include "types.h"


class pstream;

class session {
protected:
	pstream       *const t    { nullptr };
	const any_addr my_addr;
	const uint16_t my_port    { 0 };

	const any_addr their_addr;
	const uint16_t their_port { 0 };

	session_data  *callback_private_data    { nullptr };

	private_data  *application_private_data { nullptr };

	timespec       session_created { 0 };

	std::mutex     session_lock;

	std::atomic_bool is_terminating { false };

	session(pstream *const t, const any_addr & my_addr, const int my_port, const any_addr & their_addr, const int their_port, private_data *const application_private_data);

public:
	virtual ~session();

	// the names of the following 4 methods assume a server situation
	const any_addr get_their_addr() const;

	const uint16_t get_their_port() const;

	const any_addr get_my_addr() const;

	const uint16_t get_my_port() const;

	uint64_t get_hash() const;

	std::string to_str() { return myformat("%s:%d <- [%lu] -> %s:%d", get_my_addr().to_str().c_str(), get_my_port(), get_their_addr().to_str().c_str(), get_their_port()); }

	static uint64_t get_hash(const any_addr & their_addr, const uint16_t their_port, const uint16_t my_port);

	void set_is_terminating() { is_terminating = true; }

	bool get_is_terminating() { return is_terminating; }

	void set_callback_private_data(session_data *p);

	session_data *get_callback_private_data();

	pstream *get_stream_target() { return t; }

	timespec get_session_creation_time() { return session_created; }

	private_data *get_application_private_data() { return application_private_data; }

	virtual std::string get_state_name() const = 0;
};
