#include <algorithm>
#include <optional>
#include <stdarg.h>
#include <stdlib.h>
#include <string>
#include <vector>


std::string myformat(const char *const fmt, ...)
{
        char *buffer = nullptr;
        va_list ap;

        va_start(ap, fmt);
        (void)vasprintf(&buffer, fmt, ap);
        va_end(ap);

        std::string result = buffer;
        free(buffer);

        return result;
}

std::vector<std::string> split(std::string in, std::string splitter)
{
	std::vector<std::string> out;
	size_t splitter_size = splitter.size();

	for(;;)
	{
		size_t pos = in.find(splitter);
		if (pos == std::string::npos)
			break;

		std::string before = in.substr(0, pos);
		out.push_back(before);

		size_t bytes_left = in.size() - (pos + splitter_size);
		if (bytes_left == 0)
		{
			out.push_back("");
			return out;
		}

		in = in.substr(pos + splitter_size);
	}

	if (in.size() > 0)
		out.push_back(in);

	return out;
}


std::string bin_to_text(const uint8_t *p, const size_t len, const bool prefer_ascii)
{
	char  *temp = (char *)calloc(1, len * 6 + 1);
	size_t o    = 0;

	for(size_t i=0; i<len; i++) {
		if (prefer_ascii) {
			if (p[i] > 32 && p[i] < 127)
				o += snprintf(&temp[o], 7, "%c", p[i]);
			else
				o += snprintf(&temp[o], 7, "[%02x]", p[i]);
		}
		else {
			o += snprintf(&temp[o], 7, "%s%02x", i ? " " : "", p[i]);
		}
	}

	std::string out = temp;

	free(temp);

	return out;
}

std::string str_tolower(std::string s)
{
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });

	return s;
}

std::optional<std::string> find_header(const std::vector<std::string> *const lines, const std::string & key, const std::string & seperator)
{
	const std::string lkey = str_tolower(key);
	std::optional<std::string> value;

	for(auto & line : *lines) {
		auto parts = split(line, seperator);

		if (parts.size() >= 2 && str_tolower(parts.at(0)) == lkey) {
			value = line.substr(key.size() + 1);

			while(value.value().empty() == false && value.value().at(0) == ' ')
				value = value.value().substr(1);
		}
	}

	return value;
}

std::string merge(const std::vector<std::string> & in, const std::string & seperator)
{
	std::string out;

	for(auto & l : in)
		out += l + seperator;

	return out;
}

std::string replace(std::string target, const std::string & what, const std::string & by_what)
{
	for(;;) {
		std::size_t found = target.find(what);

		if (found == std::string::npos)
			break;

		std::string before = target.substr(0, found);

		std::size_t after_offset = found + what.size();
		std::string after = target.substr(after_offset);

		target = before + by_what + after;
	}

	return target;
}
