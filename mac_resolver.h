#include "any_addr.h"

class mac_resolver
{
public:
	mac_resolver();
	virtual ~mac_resolver();

	virtual any_addr get_mac(const any_addr & ip) = 0;
};
