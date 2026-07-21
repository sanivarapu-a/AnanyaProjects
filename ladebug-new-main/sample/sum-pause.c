#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

void sigint(int signo) {
    char *msg = "caught SIGINT\n";
    write(STDOUT_FILENO, msg, strlen(msg));
}

long sum(long a, long b) {
    return a + b;
}

long sum_array(long *p, int n) {
    long s = 0;
    for (int i = 0; i < n; i++) {
        s = sum(s, p[i]);
    }
    return s;
}

int main() {
    struct sigaction sa;
    sa.sa_handler = &sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    printf("pid: %d\n", getpid());

    long a[5] = {0, 1, 2, 3, 4};
    printf("a: %p\n", a);

    pause();

    long sum = sum_array(a, 5);
    printf("sum=%ld\n", sum);
}
