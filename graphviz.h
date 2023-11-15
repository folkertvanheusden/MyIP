#include <set>
#include <string>


class graphviz
{
private:
	const std::string                  filename;
	std::set<std::pair<std::string, std::string> > connections;
	std::set<std::pair<std::string, std::string> > nodes;

public:
	graphviz(const std::string & filename);
	~graphviz();

	std::string add_node(const std::string & name, const std::string & meta);
	void add_connection(const std::string & from, const std::string & to);
};
