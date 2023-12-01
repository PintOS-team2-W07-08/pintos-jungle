typedef int32_t fixed_point;

fixed_point int_to_fp(int);
int fp_to_int_round_zero(fixed_point);
int fp_to_int_round_near(fixed_point);
fixed_point fp_add_fp(fixed_point, fixed_point);
fixed_point fp_sub_fp(fixed_point, fixed_point);
fixed_point fp_add_int(fixed_point, int);
fixed_point fp_sub_int(fixed_point, int);
int64_t fp_mult_fp(fixed_point, fixed_point);       // TODO: 반환형
fixed_point fp_mult_int(fixed_point, int);
int64_t fp_div_fp(fixed_point, fixed_point);       // TODO: 반환형
fixed_point fp_div_int(fixed_point, int);
