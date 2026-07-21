#include "my_libc.h"

long sum_array(long *p, int n);
int my_strlen(const char *s);
void print_ulong(unsigned long s);

int main() {
    long a[5] = {100, 101, 102, 103, 104};
    long sum = sum_array(a, 5);

    char str1[] = "sum=";
    char newline[] = "\n";

    write(STDOUT_FILENO, str1, my_strlen(str1));
    print_ulong(sum);
    write(STDOUT_FILENO, newline, my_strlen(newline));
}
