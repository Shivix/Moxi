int test_var = 42;

int test_func(int a, int b) {
    return a + b + test_var;
}

int main(void) {
    return test_func(1, 2) == 45 ? 0 : 1;
}
