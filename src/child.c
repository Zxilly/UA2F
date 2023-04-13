#include "child.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syslog.h>
#include <stdbool.h>

static __pid_t child_pid = 0;
static u_int8_t failure_count = 0;

const u_int8_t MAX_RETRY_COUNT = 8;

static volatile sig_atomic_t graceful_exit_requested = false;

void parent_sigterm_handler(int signum) {
    graceful_exit_requested = true;
}

void child_sigterm_handler(int signum) {
    syslog(LOG_NOTICE, "Received SIGTERM, gracefully exiting.");
    exit(EXIT_SUCCESS);
}

void works_as_child() {
    while (!graceful_exit_requested) {
        if (failure_count++ > MAX_RETRY_COUNT) {
            syslog(LOG_ERR, "UA2F processor failed to start after [%d] times.", MAX_RETRY_COUNT);
            exit(EXIT_FAILURE);
        }

        child_pid = fork();
        if (child_pid < 0) {
            syslog(LOG_ERR, "Failed to fork child process");
            exit(EXIT_FAILURE);
        }

        if (child_pid == 0) {
            syslog(LOG_NOTICE, "UA2F processor start at [%d].", getpid());
            signal(SIGTERM, child_sigterm_handler);
            return;
        }

        signal(SIGTERM, parent_sigterm_handler);

        syslog(LOG_NOTICE, "Try to start UA2F processor at [%d].", child_pid);

        int exit_stat;
        waitpid(child_pid, &exit_stat, 0);

        if (WIFEXITED(exit_stat)) {
            syslog(LOG_NOTICE, "UA2F processor at [%d] exit with code [%d].", child_pid, WEXITSTATUS(exit_stat));
            if (WEXITSTATUS(exit_stat) == 0) {
                exit(EXIT_SUCCESS);
            }
        }
    }

    syslog(LOG_NOTICE, "Received SIGTERM, gracefully exited.");
    exit(EXIT_SUCCESS);
}
