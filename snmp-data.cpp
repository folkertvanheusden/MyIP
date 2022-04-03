#include "snmp-data.h"
#include "utils.h"


snmp_data_type::snmp_data_type()
{
}

snmp_data_type::~snmp_data_type()
{
}

snmp_data_type_static::snmp_data_type_static(const std::string & content) : data(content)
{
}

snmp_data_type_static::~snmp_data_type_static()
{
}

snmp_elem * snmp_data_type_static::get_data()
{
	return new snmp_octet_string(reinterpret_cast<const uint8_t *>(data.c_str()), data.size());
}

snmp_data_type_stats::snmp_data_type_stats(uint64_t *const counter) : counter(counter)
{
}

snmp_data_type_stats::~snmp_data_type_stats()
{
}

snmp_elem * snmp_data_type_stats::get_data()
{
	return new snmp_integer(*counter);
}

snmp_data_type_running_since::snmp_data_type_running_since() : running_since(get_us() / 10000)
{
}

snmp_data_type_running_since::~snmp_data_type_running_since()
{
}

snmp_elem * snmp_data_type_running_since::get_data()
{
	uint64_t now = get_us() / 10000;

	return new snmp_integer(now - running_since);  // 100ths of a second
}

snmp_data::snmp_data()
{
}

snmp_data::~snmp_data()
{
	for(auto e : data)
		delete e.second;
}

void snmp_data::add_oid(const std::string & oid, const std::string & static_data)
{
	add_oid(oid, new snmp_data_type_static(static_data));
}

void snmp_data::add_oid(const std::string & oid, snmp_data_type *const dynamic_data)
{
	std::unique_lock<std::mutex> lck(lock);

	data.insert_or_assign(oid, dynamic_data);
}
