#pragma once

#include <stdint.h>
#include <time.h>

#include "any_addr.h"
#include "types.h"


class pstream;

class session {
protected:
	pstream       *const t    { nullptr };
	const any_addr my_addr;
	const uint16_t my_port    { 0 };

	const any_addr their_addr;
	const uint16_t their_port { 0 };

	void          *callback_private_data    { nullptr };

	private_data  *application_private_data { nullptr };

	timespec       session_created { 0 };

	session(pstream *const t, const any_addr & my_addr, const int my_port, const any_addr & their_addr, const int their_port, private_data *const application_private_data);

public:
	virtual ~session();

	// the names of the following 4 methods assume a server situation
	const any_addr get_their_addr() const;

	const uint16_t get_their_port() const;

	const any_addr get_my_addr() const;

	const uint16_t get_my_port() const;

	uint64_t get_hash() const;

	static uint64_t get_hash(const any_addr & their_addr, const uint16_t their_port, const uint16_t my_port);

	void set_callback_private_data(void *p);

	void * get_callback_private_data();

	pstream *get_stream_target() { return t; }

	timespec get_session_creation_time() { return session_created; }

	private_data *get_application_private_data() { return application_private_data; }
};
