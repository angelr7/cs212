#include "threads/fixed-point.h"

const int f = (1<<14);

// Convert n to fixed point:	n * f
int  int_to_fp(int n)
{
  return n * f;
}

// Convert x to integer (rounding toward zero):	x / f
int fp_to_int(int x)
{
    return x / f;
}

// Convert x to integer (rounding to nearest):	(x + f / 2) / f if x >= 0,
// (x - f / 2) / f if x <= 0.
int fp_to_int_round_nearest(int x)
{
  if (x >= 0)
    return (x + f / 2) / f;
  return (x - f / 2) / f;
}

// Add x and y:	x + y
int add_fp_to_fp(int x, int y)
{
  return x + y;
}

// Subtract y from x:	x - y
int subtract_fp_to_fp(int x, int y)
{
  return x - y;
}

// Add x and n:	x + n * f
int add_fp_to_int(int x, int n)
{
  return x + n * f;
}

// Subtract n from x:	x - n * f
int subtract_int_from_fp(int x, int n)
{
  return x - n * f;
}

// Multiply x by y:	((int64_t) x) * y / f
int multiply_fp_by_fp(int x, int y)
{
  return ((int64_t) x) * y / f;
}

// Multiply x by n:	x * n
int multiply_fp_by_int(int x, int n)
{
  return x * n;
}

// Divide x by y:	((int64_t) x) * f / y
int divide_fp_by_fp(int x, int y)
{
  return ((int64_t) x) * f / y;
}

// Divide x by n:	x / n
int divide_fp_by_int(int x, int n)
{
  return x / n;
}