#pragma once

#include <map>
#include <mutex>
#include <stdint.h>

#include "snmp-elem.h"


class snmp_data_type
{
protected:
	int         index { -1 };
	std::string oid;

	std::map<std::string, snmp_data_type *> children;

public:
	snmp_data_type();
	virtual ~snmp_data_type();

	virtual snmp_elem * get_data();

	std::map<std::string, snmp_data_type *> * get_children();
	void        set_tree_data(const int index, const std::string & oid);
	int         get_index();
	std::string get_oid();
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

	std::string get_sibling(std::map<std::string, snmp_data_type *> & m, const int who);

	void walk_tree(snmp_data_type & node);

public:
	snmp_data();
	virtual ~snmp_data();

	void register_oid(const std::string & oid, const std::string & static_data);
	void register_oid(const std::string & oid, snmp_data_type *const e);

	std::optional<snmp_elem *> find_by_oid(const std::string & oid);
	std::string find_next_oid(const std::string & oid);

	void dump_tree();
};
