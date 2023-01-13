#include <string>
#include <tuple>


std::tuple<pid_t, int, int> exec_with_pipe(const std::string & command, const std::string & dir, const std::vector<std::string> & envs);
