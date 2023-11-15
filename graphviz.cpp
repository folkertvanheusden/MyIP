#include <stdio.h>

#include "graphviz.h"
#include "utils.h"


graphviz::graphviz(const std::string & filename) : filename(filename)
{
}

graphviz::~graphviz()
{
	if (filename.empty() == false) {
		FILE *fh = fopen(filename.c_str(), "w");
		if (!fh)
			error_exit(true, "Failed creating %s", filename.c_str());

		fprintf(fh, "digraph {\n");

		for(auto & node: nodes)
			fprintf(fh, "\t\"%s\" [label=\"%s\"]\n", node.first.c_str(), node.second.c_str());

		for(auto & connection: connections)
			fprintf(fh, "\t\"%s\" -> \"%s\"\n", connection.first.c_str(), connection.second.c_str());

		fprintf(fh, "}\n");

		fclose(fh);
	}
}

std::string graphviz::add_node(const std::string & name, const std::string & meta)
{
	nodes.insert({ name, meta });

	return name;
}

void graphviz::add_connection(const std::string & from, const std::string & to)
{
	connections.insert({ from, to });
}
