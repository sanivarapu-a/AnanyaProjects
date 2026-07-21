#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <assert.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <target> [args...]\n", argv[0]);
        exit(1);
    }

    // Implement icount
    pid_t pid;

    if ((pid = fork()) == 0) { // child
        /* Target */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace_traceme");
            exit(1);
        }

        execv(argv[1], argv + 1);
        perror("execv");
        exit(1);
    }
    else if (pid < 0) {
        perror("fork");
        exit(1);
    }

    int wstatus;
    long icount = 1;

    
    // Wait for child to be stopped after execv().
    if (waitpid(pid, &wstatus, 0) < 0) {
        perror("waitpid");
        exit(1);
    }
    assert(WIFSTOPPED(wstatus));

    while (1) {

        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) {
            perror("ptrace_singlestep");
            exit(1);
        }

        if (waitpid(pid, &wstatus, 0) < 0) {
            perror("waitpid");
            exit(1);
        }

        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            break;
        }

        
        if (WSTOPSIG(wstatus) != SIGTRAP) { // is this necessary
            continue;
        }  

        icount += 1;
    }

    printf("icount: %ld\n", icount);
    return 0;
}
