#include "fixed_point.h"
int f = (2<<14);

fixed_point int_to_fp(int n) {
    n = n * f;
}

int fp_to_int_round_zero(fixed_point x) {
    return x / f;
}

int fp_to_int_round_near(fixed_point x) {
    if(x >= 0) return(x + f / 2) / f;
    else return(x - f / 2) / f;
}

fixed_point fp_add_fp(fixed_point x, fixed_point y) {
    return x + y;
}

fixed_point fp_sub_fp(fixed_point x, fixed_point y) {
    return x - y;
}

fixed_point fp_add_int(fixed_point x, int n) {
    return (x + int_to_fp(n));
}

fixed_point fp_sub_int(fixed_point x, int n) {
    return (x - int_to_fp(n));
}

int64_t fp_mult_fp(fixed_point x, fixed_point y) {
    return ((int64_t) x) * y / f;
}

fixed_point fp_mult_int(fixed_point x, int n) {
    return x * n;
}

int64_t fp_div_fp(fixed_point x, fixed_point y) {
    return ((int64_t) x) * f / y;
}

fixed_point fp_div_int(fixed_point x, int n) {
    return x / n;
}
