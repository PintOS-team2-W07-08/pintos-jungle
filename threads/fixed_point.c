#include <stdint.h>
#include "threads/fixed_point.h"

#define F (1<<14)

fixed_point int_to_fp(int n) {
    fixed_point fn = n * F;
    return fn;
}

int fp_to_int_round_zero(fixed_point x) {
    return x / F;
}

int fp_to_int_round_near(fixed_point x) {
    int result;
    if(x >= 0){
        result  = ((x + (F / 2)) / F);
    }
    else{
        result = ((x - (F / 2)) / F);
    } 
    return result;
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

fixed_point fp_mult_fp(fixed_point x, fixed_point y) {
    return ((int64_t) x) * y / F;
}

fixed_point fp_mult_int(fixed_point x, int n) {
    return x * n;
}

fixed_point fp_div_fp(fixed_point x, fixed_point y) {
    return ((int64_t) x) * F / y;
}

fixed_point fp_div_int(fixed_point x, int n) {
    return x / n;
}
