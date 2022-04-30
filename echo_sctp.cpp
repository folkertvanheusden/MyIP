#include "sctp.h"


void sctp_echo_init()
{
}

void sctp_echo_deinit()
{
}

void sctp_echo_new_session(sctp *const sctp_, sctp::sctp_session *const session)
{
}

bool sctp_echo_new_data(sctp *const sctp_, sctp::sctp_session *const session, buffer_in data)
{
	return sctp_->send_data(session, data);
}

void sctp_echo_session_closed_1(sctp *const sctp_, sctp::sctp_session *const session)
{
}

void sctp_echo_session_closed_2(sctp *const sctp_, sctp::sctp_session *const session)
{
}

sctp::sctp_port_handler_t sctp_echo_get_handler()
{
	sctp::sctp_port_handler_t meta;

	meta.init             = sctp_echo_init;
	meta.deinit           = sctp_echo_deinit;
	meta.new_session      = sctp_echo_new_session;
	meta.new_data         = sctp_echo_new_data;
	meta.session_closed_1 = sctp_echo_session_closed_1;
	meta.session_closed_2 = sctp_echo_session_closed_2;
	
	return meta;
}
