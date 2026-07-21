#ifndef UNIT_TEST
#include "my_libc.h"
#else
#include <unistd.h>
#include <limits.h>
#endif

int my_strlen(const char *s);

void print_ulong(unsigned long s) {
    if (s == 0) {
        char z = '0';
        write(STDOUT_FILENO, &z, 1);
        return;
    }

    char out[22];
    out[21] = '\0';

    char *p = &out[20];
    while (s > 0) {
        *p-- = '0' + (s % 10);
        s /= 10;
    }
    p++;

    write(STDOUT_FILENO, p, my_strlen(p));

}

#ifdef UNIT_TEST

int main() {
    print_ulong(ULONG_MAX);
}

#endif
