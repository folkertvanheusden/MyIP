#include <algorithm>
#include <assert.h>

#include "snmp-data.h"
#include "utils.h"


snmp_data_type::snmp_data_type()
{
}

snmp_data_type::~snmp_data_type()
{
}

std::map<std::string, snmp_data_type *> * snmp_data_type::get_children()
{
	return &children;
}

void snmp_data_type::set_tree_data(const int index, const std::string & oid)
{
	this->index = index;
	this->oid   = oid;
}

snmp_elem * snmp_data_type::get_data()
{
	return nullptr;
}

int snmp_data_type::get_index()
{
	return index;
}

std::string snmp_data_type::get_oid()
{
	return oid;
}

snmp_data_type_static::snmp_data_type_static(const std::string & content) :
	data(content)
{
}

snmp_data_type_static::~snmp_data_type_static()
{
}

snmp_elem * snmp_data_type_static::get_data()
{
	return new snmp_octet_string(reinterpret_cast<const uint8_t *>(data.c_str()), data.size());
}

snmp_data_type_stats::snmp_data_type_stats(uint64_t *const counter) :
	counter(counter)
{
}

snmp_data_type_stats::~snmp_data_type_stats()
{
}

snmp_elem * snmp_data_type_stats::get_data()
{
	return new snmp_integer(*counter);
}

snmp_data_type_running_since::snmp_data_type_running_since():
	running_since(get_us() / 10000)
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

void snmp_data::register_oid(const std::string & oid, snmp_data_type *const e)
{
	assert(e);

	std::map<std::string, snmp_data_type *> *p_lut = &data;

	std::vector<std::string>     parts = split(oid, ".");

	std::string                  cur_oid;

	std::unique_lock<std::mutex> lck(lock);

	for(size_t i=0; i<parts.size(); i++) {
		if (cur_oid.empty() == false)
			cur_oid += ".";

		cur_oid += parts.at(i);

		auto it = p_lut->find(cur_oid);

		if (it == p_lut->end()) {
			snmp_data_type *temp_e = new snmp_data_type();
			temp_e->set_tree_data(i, cur_oid);

			p_lut->insert({ cur_oid, temp_e});

			p_lut = temp_e->get_children();
		}
		else {
			p_lut = it->second->get_children();
		}
	}
}

void snmp_data::register_oid(const std::string & oid, const std::string & static_data)
{
	register_oid(oid, new snmp_data_type_static(static_data));
}

std::optional<snmp_elem *> snmp_data::find_by_oid(const std::string & oid)
{
	std::unique_lock<std::mutex> lck(lock);

	std::map<std::string, snmp_data_type *> *p_lut = &data;

	std::vector<std::string> parts = split(oid, ".");

	std::string cur_oid;

	for(size_t i=0; i<parts.size(); i++) {
		if (cur_oid.empty() == false)
			cur_oid += ".";

		cur_oid += parts.at(i);

		auto it = p_lut->find(cur_oid);

		if (it == p_lut->end())
			break;

		if (i == parts.size() - 1)
			return it->second->get_data();

		p_lut = it->second->get_children();
	}

	return { };
}

std::string snmp_data::find_next_oid(const std::string & oid)
{
	std::string out;

	std::unique_lock<std::mutex> lck(lock);

	std::map<std::string, snmp_data_type *> *p_lut = &data;

	std::vector<std::string> parts = split(oid, ".");

	std::string cur_oid;

	for(size_t i=0; i<parts.size(); i++) {
		if (cur_oid.empty() == false)
			cur_oid += ".";

		cur_oid += parts.at(i);

		auto it = p_lut->find(cur_oid);

		if (it == p_lut->end())
			return "";

		p_lut = it->second->get_children();
	}

	if (p_lut->empty())
		return "";

	return p_lut->begin()->second->get_oid();
}

void snmp_data::walk_tree(snmp_data_type & node)
{
	std::string cur_oid = node.get_oid();

	fprintf(stderr, " \"%s\" [shape=circle];\n", cur_oid.c_str());

	for(auto k : *node.get_children()) {
		std::string child_oid = k.first;
	
		fprintf(stderr, " \"%s\" -> \"%s\";\n", cur_oid.c_str(), child_oid.c_str());

		walk_tree(*k.second);
	}
}

void snmp_data::dump_tree()
{
	fprintf(stderr, "digraph test {\n");

	walk_tree(*data.begin()->second);

	fprintf(stderr, "}\n");
}
