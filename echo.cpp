#include "application.h"
#include "pstream.h"
#include "types.h"


void echo_init()
{
}

void echo_deinit()
{
}

bool echo_new_session(pstream *const ps, session *const session)
{
	return true;
}

bool echo_new_data(pstream *const ps, session *const session, buffer_in data)
{
	const int      len = data.get_n_bytes_left();
	const uint8_t *d   = data.get_bytes(len);

	return ps->send_data(session, d, len);
}

bool echo_session_closed_1(pstream *const ps, session *const session)
{
	return true;
}

bool echo_session_closed_2(pstream *const ps, session *const session)
{
	return true;
}

port_handler_t echo_get_handler()
{
	port_handler_t meta { 0 };

	meta.init             = echo_init;
	meta.deinit           = echo_deinit;
	meta.new_session      = echo_new_session;
	meta.new_data         = echo_new_data;
	meta.session_closed_1 = echo_session_closed_1;
	meta.session_closed_2 = echo_session_closed_2;
	
	return meta;
}
