#include <algorithm>
#include <assert.h>

#include "snmp-data.h"
#include "utils.h"


static ssize_t find_oid_in_vector(std::vector<snmp_data_type *> *vec, const std::string & oid)
{
	ssize_t n = vec->size();

	for(ssize_t i=0; i<n; i++) {
		if (vec->at(i)->get_oid() == oid)
			return i;
	}

	return -1;
}

snmp_data_type::snmp_data_type()
{
}

snmp_data_type::~snmp_data_type()
{
}

std::vector<snmp_data_type *> * snmp_data_type::get_children()
{
	return &data;
}

void snmp_data_type::set_tree_data(const std::string & oid)
{
	this->oid = oid;

	std::size_t dot = oid.rfind('.');
	if (dot != std::string::npos)
		oid_idx = atoi(oid.substr(dot + 1).c_str());
}

snmp_elem * snmp_data_type::get_data()
{
	return nullptr;
}

std::string snmp_data_type::get_oid() const
{
	return oid;
}

int snmp_data_type::get_oid_idx() const
{
	return oid_idx;
}

snmp_data_type_static::snmp_data_type_static(const std::string & content) :
	is_string(true),
	data(content),
	data_int(-1)
{
}

snmp_data_type_static::snmp_data_type_static(const snmp_integer::snmp_integer_type type, const int content) :
	is_string(false),
	type(type),
	data_int(content)
{
}

snmp_data_type_static::~snmp_data_type_static()
{
}

snmp_elem * snmp_data_type_static::get_data()
{
	if (is_string)
		return new snmp_octet_string(reinterpret_cast<const uint8_t *>(data.c_str()), data.size());

	return new snmp_integer(snmp_integer::si_integer, data_int);
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
	return new snmp_integer(snmp_integer::si_counter, *counter);
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

	return new snmp_integer(snmp_integer::si_integer, now - running_since);  // 100ths of a second
}

snmp_data::snmp_data()
{
}

snmp_data::~snmp_data()
{
	// delete tree 'data'
}

void snmp_data::register_oid(const std::string & oid, snmp_data_type *const e)
{
	assert(e);

	std::vector<snmp_data_type *> *p_lut = &data;

	std::vector<std::string>       parts = split(oid, ".");

	std::string                    cur_oid;

	std::unique_lock<std::mutex>   lck(lock);

	for(size_t i=0; i<parts.size(); i++) {
		if (cur_oid.empty() == false)
			cur_oid += ".";

		cur_oid += parts.at(i);

		ssize_t idx = find_oid_in_vector(p_lut, cur_oid);

		if (idx == -1) {
			snmp_data_type *temp_e = i == parts.size() - 1 ? e : new snmp_data_type();
			temp_e->set_tree_data(cur_oid);

			bool inserted = false;

			for(size_t i=0; i<p_lut->size(); i++) {
				if (temp_e->get_oid_idx() < p_lut->at(i)->get_oid_idx()) {
					inserted = true;
					p_lut->insert(p_lut->begin() + i, temp_e);
					break;
				}
			}

			if (!inserted)
				p_lut->push_back(temp_e);

			p_lut = temp_e->get_children();
		}
		else {
			p_lut = p_lut->at(idx)->get_children();
		}
	}
}

void snmp_data::register_oid(const std::string & oid, const std::string & static_data)
{
	register_oid(oid, new snmp_data_type_static(static_data));
}

void snmp_data::register_oid(const std::string & oid, const snmp_integer::snmp_integer_type type, const int static_data)
{
	register_oid(oid, new snmp_data_type_static(type, static_data));
}

std::optional<snmp_elem *> snmp_data::find_by_oid(const std::string & oid)
{
	std::unique_lock<std::mutex> lck(lock);

	std::vector<snmp_data_type *> *p_lut = &data;

	std::vector<std::string> parts = split(oid, ".");

	std::string cur_oid;

	for(size_t i=0; i<parts.size(); i++) {
		if (cur_oid.empty() == false)
			cur_oid += ".";

		cur_oid += parts.at(i);

		ssize_t idx = find_oid_in_vector(p_lut, cur_oid);

		if (idx == -1)
			break;

		if (i == parts.size() - 1)
			return p_lut->at(idx)->get_data();

		p_lut = p_lut->at(idx)->get_children();
	}

	return { };
}

std::string snmp_data::find_next_oid(const std::string & oid)
{
	std::unique_lock<std::mutex> lck(lock);

	std::vector<snmp_data_type *> *p_lut = &data;
	snmp_data_type *parent = nullptr;

	std::vector<std::string> parts = split(oid, ".");

	std::string cur_oid;

	std::vector<std::pair<snmp_data_type *, ssize_t> > branch;

	for(size_t i=0; i<parts.size(); i++) {
		if (cur_oid.empty() == false)
			cur_oid += ".";

		cur_oid += parts.at(i);

		ssize_t idx = find_oid_in_vector(p_lut, cur_oid);

		if (idx == -1)
			break;

		branch.push_back({ parent, idx });

		parent = p_lut->at(idx);
		p_lut = parent->get_children();
	}

	// search for end of branch
	while(p_lut->empty() == false) {
		branch.push_back({ parent, 0 });

		parent = p_lut->at(0);
		p_lut = parent->get_children();
	}

	if (parent->get_oid() != oid)
		return parent->get_oid();

	branch.push_back({ parent, 0 });

	// go to a sibbling
	while(branch.empty() == false) {
		snmp_data_type *element = branch.back().first;
		ssize_t         index   = branch.back().second;

		if (element == nullptr) {  // top node
			assert(branch.size() == 1);
			break;
		}

		branch.pop_back();

		if (index + 1 < element->get_children()->size()) {
			ssize_t nr = index + 1;

			do {
				element = element->get_children()->at(nr);
				nr = 0;
			}
			while(element->get_children()->empty() == false);

			return element->get_oid();
		}
	}

	return "";
}

void snmp_data::walk_tree(snmp_data_type & node)
{
	std::string cur_oid = node.get_oid();

	fprintf(stderr, " \"%s\" [shape=circle];\n", cur_oid.c_str());

	for(auto k : *node.get_children()) {
		std::string child_oid = k->get_oid();
	
		fprintf(stderr, " \"%s\" -> \"%s\";\n", cur_oid.c_str(), child_oid.c_str());

		walk_tree(*k);
	}
}

void snmp_data::dump_tree()
{
	fprintf(stderr, "digraph test {\n");

	walk_tree(*data.at(0));

	fprintf(stderr, "}\n");
}
