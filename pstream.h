#pragma once

#include <condition_variable>
#include <map>
#include <shared_mutex>
#include <stdint.h>

#include "session.h"


class pstream
{
protected:
	mutable std::shared_mutex     sessions_lock;
	std::condition_variable_any   sessions_cv;
	// the key is an 'internal id'
	std::map<uint64_t, session *> sessions;

public:
	pstream() { }
	virtual ~pstream() { }

	virtual bool send_data(session *const s, const uint8_t *const data, const size_t len) = 0;

	virtual void end_session(session *const ts) = 0;

	auto get_sessions_locked() const { sessions_lock.lock(); return &sessions; }

	void sessions_unlock() { sessions_lock.unlock(); }
};
