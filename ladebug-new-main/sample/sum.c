#include <stdio.h>

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
    long a[5] = {0, 1, 2, 3, 4};
    long sum = sum_array(a, 5);
    printf("sum=%ld\n", sum);
}
