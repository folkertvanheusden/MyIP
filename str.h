#include <optional>
#include <string>
#include <vector>


std::string                myformat(const char *const fmt, ...);
std::vector<std::string>   split(std::string in, std::string splitter);
std::string                replace(std::string target, const std::string & what, const std::string & by_what);
std::string                bin_to_text(const uint8_t *p, const size_t len, const bool prefer_ascii = false);
std::string                merge(const std::vector<std::string> & in, const std::string & seperator);
std::string                str_tolower(std::string s);
std::optional<std::string> find_header(const std::vector<std::string> *const lines, const std::string & key, const std::string & seperator = ":");
