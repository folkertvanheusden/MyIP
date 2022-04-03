#include "snmp-static.h"

snmp_static::snmp_static()
{
}

snmp_static::~snmp_static()
{
}

void snmp_static::add_data(const std::string & oid, const std::string & data)
{
	std::unique_lock<std::mutex> lck(lock);

	static_data.insert_or_assign(oid, data);
}

std::optional<std::string> snmp_static::get_oid(const std::string & oid)
{
	std::unique_lock<std::mutex> lck(lock);

	auto it = static_data.find(oid);
	if (it == static_data.end())
		return { };

	return it->second;
}
