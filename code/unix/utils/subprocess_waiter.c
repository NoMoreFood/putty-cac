/*
 * Unix implementation of SubprocessWaiter. This module catches
 * SIGCHLD and uses a self-pipe to do the main handling of it in the
 * primary event loop thread. It expects the uxsel mechanism to exist,
 * and also expects nobody else to be messing with SIGCHLD.
 */

#include "putty.h"
#include "tree234.h"

#include <unistd.h>
#include <sys/wait.h>

struct SubprocessWaiter {
    pid_t pid;
    SubprocessWaiterCallback callback;
    void *cbctx;
};

tree234 *waiters_by_pid;

static int subproc_waiter_compare_by_pid(void *av, void *bv)
{
    SubprocessWaiter *a = (SubprocessWaiter *)av;
    SubprocessWaiter *b = (SubprocessWaiter *)bv;

    if (a->pid < b->pid)
        return -1;
    else if (a->pid > b->pid)
        return +1;
    return 0;
}

static int subproc_waiter_find_by_pid(void *av, void *bv)
{
    pid_t a = *(pid_t *)av;
    SubprocessWaiter *b = (SubprocessWaiter *)bv;

    if (a < b->pid)
        return -1;
    else if (a > b->pid)
        return +1;
    return 0;
}


static int sigchld_pipe[2] = { -1, -1 };   /* obviously bogus initial val */

static void sigchld_handler(int signum)
{
    if (write(sigchld_pipe[1], "x", 1) <= 0) {
        /*
         * We check the return value of write() to inhibit a gcc
         * warning, but we expect that the only plausible error is
         * EAGAIN/EWOULDBLOCK if the pipe has already filled up. Even
         * that isn't _very_ likely, unless >8000 subprocesses
         * terminate between passes of the event loop. But if it does
         * happen, there's no problem, because we respond to data in
         * this pipe by waiting for all available processes, so after
         * this handler is called, all we need to ensure is that _at
         * least one_ notification reaches the main event loop - and
         * if the pipe buffer is already full, then _a fortiori_ it's
         * non-empty, so that's enough to guarantee what we want
         * anyway.
         *
         * This is a long-winded way of explaining why we do nothing
         * in this error-handling block.
         */
    }
}

void subproc_waiter_force_wait(void)
{
    while (1) {
        int status;
        pid_t pid = waitpid(-1, &status, WNOHANG);

        if (pid <= 0)
            break;                 /* nothing more to wait for */

        int exittype;
        uint32_t exitdata;
        if (WIFEXITED(status)) {
            exittype = EXITTYPE_NORMAL;
            exitdata = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            exittype = EXITTYPE_SIGNAL;
            exitdata = WTERMSIG(status);
        } else {
            /* We only notify for _terminations_ */
            continue;
        }

        SubprocessWaiter *waiter = find234(
            waiters_by_pid, &pid, subproc_waiter_find_by_pid);
        if (waiter && waiter->callback)
            waiter->callback(waiter->cbctx, exittype, exitdata);
    }
}

static void sigchld_select_result(int fd, int event)
{
    if (fd == sigchld_pipe[0]) {
        char c[PIPE_BUF];

        /* Empty the pipe buffer. */
        while (read(sigchld_pipe[0], c, sizeof(c)) > 0)
            /* do nothing */;

        /* Now wait for all available subprocesses. */
        subproc_waiter_force_wait();
    }
}

void subproc_waiter_force_setup(void)
{
    static bool setup = false;
    if (!setup) {
        if (pipe(sigchld_pipe) < 0) {
            perror("pipe");
            exit(1);
        }
        cloexec(sigchld_pipe[0]);
        cloexec(sigchld_pipe[1]);
        nonblock(sigchld_pipe[0]);
        nonblock(sigchld_pipe[1]);

        putty_signal(SIGCHLD, sigchld_handler);

        waiters_by_pid = newtree234(subproc_waiter_compare_by_pid);

        /* We don't call uxsel_set here, because this function might
         * have been called too early, e.g. in pty.c. We leave that
         * for subproc_waiter_from_pid. */

        setup = true;
    }
}

SubprocessWaiter *subproc_waiter_from_pid(pid_t pid)
{
    subproc_waiter_force_setup();
    uxsel_set(sigchld_pipe[0], SELECT_R, sigchld_select_result);

    SubprocessWaiter *waiter = snew(SubprocessWaiter);
    waiter->pid = pid;
    waiter->callback = NULL;
    waiter->cbctx = NULL;
    SubprocessWaiter *added = add234(waiters_by_pid, waiter);
    assert(added == waiter);
    return waiter;
}

void subproc_waiter_set_callback(
    SubprocessWaiter *waiter, SubprocessWaiterCallback cb, void *cbctx)
{
    waiter->callback = cb;
    waiter->cbctx = cbctx;
}

void subproc_waiter_free(SubprocessWaiter *waiter)
{
    del234(waiters_by_pid, waiter);
    sfree(waiter);
}
