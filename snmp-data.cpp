#include <algorithm>

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

void snmp_data::add_oid(const std::string & oid, const std::string & static_data)
{
	add_oid(oid, new snmp_data_type_static(static_data));
}

void snmp_data::add_oid(const std::string & oid, snmp_data_type *const dynamic_data)
{
	std::unique_lock<std::mutex> lck(lock);

	data.insert_or_assign(oid, dynamic_data);
}

std::optional<snmp_elem *> snmp_data::find_by_oid(const std::string & oid)
{
	std::unique_lock<std::mutex> lck(lock);

	std::map<std::string, snmp_data_type *> *p_lut = &data;

	std::vector<std::string> parts = split(oid, ".");

	for(size_t i=0; i<parts.size(); i++) {
		auto it = p_lut->find(parts.at(i));

		if (it == p_lut->end())
			break;

		if (i == parts.size() - 1)
			return it->second->get_data();

		p_lut = it->second->get_children();
	}

	return { };
}

std::string snmp_data::get_sibling(std::map<std::string, snmp_data_type *> & m, const int who)
{
	if (m.empty())
		return "";

	struct int_cmp {
		bool operator()(const std::pair<std::string, snmp_data_type *> & lhs, const std::pair<std::string, snmp_data_type *> & rhs) {
			return lhs.second->get_index() < rhs.second->get_index();
		}
	};

	std::vector<std::pair<std::string, snmp_data_type *> > temp(m.begin(), m.end());
	std::stable_sort(temp.begin(), temp.end(), int_cmp());

	for(size_t i=0; i<temp.size(); i++) {
		if (temp.at(i).second->get_index() > who)
			return temp.at(i).second->get_oid();
	}

	return "";
}

std::string snmp_data::find_next_oid(const std::string & oid)
{
	std::string out;

	std::unique_lock<std::mutex> lck(lock);

	std::map<std::string, snmp_data_type *> *p_lut = &data;

	std::vector<std::string> parts = split(oid, ".");

	for(size_t i=0; i<parts.size(); i++) {
		auto it = p_lut->find(parts.at(i));

		if (it == p_lut->end())
			break;

		if (i == parts.size() - 1) {
			out = get_sibling(*p_lut, atoi(parts.at(i).c_str()));

			if (out.empty() == true) {
				p_lut = it->second->get_children();

				out = get_sibling(*p_lut, -1);
			}

			break;
		}

		p_lut = it->second->get_children();
	}

	lock.unlock();

	return out;
}
