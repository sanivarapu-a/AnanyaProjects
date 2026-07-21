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
