#include <map>
#include <mutex>
#include <optional>
#include <string>


class snmp_static
{
private:
	std::mutex lock;
	std::map<std::string, std::string> static_data;

public:
	snmp_static();
	virtual ~snmp_static();

	void add_data(const std::string & oid, const std::string & data);

	std::optional<std::string> get_oid(const std::string & oid);
};
