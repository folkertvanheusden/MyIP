#include <map>
#include <mutex>
#include <stdint.h>

#include "snmp-elem.h"


class snmp_data_type
{
public:
	snmp_data_type();
	virtual ~snmp_data_type();

	virtual snmp_elem * get_data() = 0;
};

class snmp_data_type_static : public snmp_data_type
{
private:
	const std::string data;

public:
	snmp_data_type_static(const std::string & content);
	~snmp_data_type_static();

	snmp_elem * get_data() override;
};

class snmp_data_type_stats : public snmp_data_type
{
private:
	uint64_t *const counter;

public:
	snmp_data_type_stats(uint64_t *const counter);
	~snmp_data_type_stats();

	snmp_elem * get_data() override;
};

class snmp_data_type_running_since : public snmp_data_type
{
private:
	const uint64_t running_since;

public:
	snmp_data_type_running_since();
	~snmp_data_type_running_since();

	snmp_elem * get_data() override;
};

class snmp_data
{
private:
	std::map<std::string, snmp_data_type *> data;
	std::mutex     lock;

public:
	snmp_data();
	virtual ~snmp_data();

	void add_oid(const std::string & oid, const std::string & static_data);

	void add_oid(const std::string & oid, snmp_data_type *const dynamic_data);
};
