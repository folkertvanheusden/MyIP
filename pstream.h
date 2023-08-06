#pragma once

#include <condition_variable>
#include <jansson.h>
#include <map>
#include <shared_mutex>
#include <stdint.h>

#include "session.h"


class pstream
{
protected:
	mutable std::shared_mutex     sessions_lock;
	// the key is an 'internal id'
	std::map<uint64_t, session *> sessions;

public:
	pstream() { }
	virtual ~pstream() { }

	virtual bool send_data(session *const s, const uint8_t *const data, const size_t len) = 0;

	virtual void end_session(session *const ts) = 0;

	virtual json_t *get_state_json(session *const ts) = 0;

	auto get_sessions_locked() const { sessions_lock.lock_shared(); return &sessions; }

	void sessions_unlock() { sessions_lock.unlock_shared(); }
};
