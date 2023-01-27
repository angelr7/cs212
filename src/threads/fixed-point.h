#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include "threads/thread.h"

uint32_t  int_to_fp(int n);
int fp_to_int(uint32_t x);
int fp_to_int_round_nearest(uint32_t x);
uint32_t add_fp_to_fp(uint32_t x, uint32_t y);
uint32_t subtract_fp_to_fp(uint32_t x, uint32_t y);
uint32_t add_fp_to_int(uint32_t x, int n);
uint32_t subtract_int_from_fp(uint32_t x, int n);
uint32_t multiply_fp_by_fp(uint32_t x, uint32_t y);
uint32_t multiply_fp_by_int(uint32_t x, int n);
uint32_t divide_fp_by_fp(uint32_t x, uint32_t y);
uint32_t divide_fp_by_int(uint32_t x, int n);


#endif /* threads/fixed-point.h */
