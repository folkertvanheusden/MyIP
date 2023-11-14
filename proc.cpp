#include <fcntl.h>
#include <pty.h>
#include <stdlib.h>
#include <string>
#include <tuple>
#include <unistd.h>
#include <vector>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "str.h"
#include "utils.h"


// this code needs more error checking TODO
std::tuple<pid_t, int, int> exec_with_pipe(const std::string & command, const std::string & dir, const std::vector<std::string> & envs)
{
	int fd_master { -1 };

	pid_t pid = forkpty(&fd_master, nullptr, nullptr, nullptr);
	if (pid == -1)
		error_exit(true, "exec_with_pipe: forkpty failed");

        if (pid == 0) {
                setsid();

                if (dir.empty() == false && chdir(dir.c_str()) == -1)
                        error_exit(true, "exec_with_pipe: chdir to %s for %s failed", dir.c_str(), command.c_str());

                close(2);
                (void)open("/dev/null", O_WRONLY);

                // TODO: a smarter way?
                int fd_max = sysconf(_SC_OPEN_MAX);
                for(int fd=3; fd<fd_max; fd++)
                        close(fd);

                std::vector<std::string> parts = split(command, " ");

                size_t n_args = parts.size();
                char **pars = new char *[n_args + 1];
                for(size_t i=0; i<n_args; i++)
                        pars[i] = const_cast<char *>(parts.at(i).c_str());
                pars[n_args] = nullptr;

		size_t n_env = envs.size();
                char **env = new char *[n_env + 1];
                for(size_t i=0; i<n_env; i++)
                        env[i] = const_cast<char *>(envs.at(i).c_str());
                env[n_env] = nullptr;

                if (execvpe(pars[0], &pars[0], env) == -1) {
			std::string error = myformat("CANNOT INVOKE \"%s\"!", command.c_str());

			write(fd_master, error.c_str(), error.size());

                        error_exit(true, "Failed to invoke %s", command.c_str());
		}
        }

        std::tuple<pid_t, int, int> out(pid, fd_master, fd_master);

        return out;
}

void run(const std::string & what)
{
	pid_t child = fork();
	if (child == -1)
		error_exit(true, "fork failed");

	if (child == 0) {
		setsid();

		int rc = system(what.c_str());
		if (rc == 127)
			error_exit(false, "system(%s) failed (%d)\n", what.c_str(), rc);

		exit(0);
	}
}
