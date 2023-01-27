#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include "threads/thread.h"

int  int_to_fp(int n);
int fp_to_int(int x);
int fp_to_int_round_nearest(int x);
int add_fp_to_fp(int x, int y);
int subtract_fp_to_fp(int x, int y);
int add_fp_to_int(int x, int n);
int subtract_int_from_fp(int x, int n);
int multiply_fp_by_fp(int x, int y);
int multiply_fp_by_int(int x, int n);
int divide_fp_by_fp(int x, int y);
int divide_fp_by_int(int x, int n);


#endif /* threads/fixed-point.h */
