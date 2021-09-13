#include "sip_register.h"
#include "utils.h"

sip_register::sip_register(udp *const u, const std::string & upstream_sip_server, const std::string & upstream_sip_user, const std::string & upstream_sip_password, const any_addr & myip, const int myport, const int interval) :
	u(u),
	upstream_server(upstream_sip_server), username(upstream_sip_user), password(upstream_sip_password),
	myip(myip), myport(myport),
	interval(interval)
{
	th = new std::thread(std::ref(*this));
}

sip_register::~sip_register()
{
	stop_flag = true;
	th->join();
	delete th;
}

void sip_register::operator()()
{
	std::string work = upstream_server;

	any_addr tgt_addr;
	int tgt_port = 5060;

	std::string::size_type colon = work.find(':');
	if (colon != std::string::npos) {
		tgt_port = atoi(work.substr(colon + 1).c_str());
		work = work.substr(0, colon);
	}

	tgt_addr = parse_address(work.c_str(), 4, ".", 10);

	std::string out;
	out += "REGISTER sip:" + tgt_addr.to_str() + " SIP/2.0\r\n";
	out += "CSeq: 1 REGISTER\r\n";
	out += "Via: SIP/2.0/UDP " + myip.to_str() + ":" + myformat("%d", myport) + "\r\n";
	out += "User-Agent: MyIP\r\n";
	out += "From: <sip:" + username + "@" + tgt_addr.to_str() + ">;tag=277FD9F0-2607D15D\r\n"; // TODO
	out += "Call-ID: e4ec6031-99e1\r\n"; // TODO
	out += "To: <sip:" + username + "@" + tgt_addr.to_str() + ">\r\n";
	out += "Contact: <sip:" + username + "@" + myip.to_str() + ">;q=1\r\n";
	out += "Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,REFER,MESSAGE,INFO,PING\r\n";
	out += "Expires: 60\r\n";
	out += "Content-Length: 0\r\n";
	out += "Max-Forwards: 70\r\n\r\n";

	while(!stop_flag) {
		u->transmit_packet(tgt_addr, tgt_port, myip, myport, (const uint8_t *)out.c_str(), out.size());

		for(int i=0; i<interval * 2 && !stop_flag; i++)
			myusleep(500 * 1000);
	}
}
