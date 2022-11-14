#pragma once

#include <stdint.h>

#include "session.h"


class pstream
{
public:
	pstream() { }
	virtual ~pstream() { }

	virtual bool send_data(session *const s, const uint8_t *const data, const size_t len) = 0;

	virtual void end_session(session *const ts) = 0;
};
