#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include "threads/thread.h"

int calculate_priority(struct thread *t);
int calculate_recent_cpu(struct thread *t);
int calculate_load_avg(struct thread *t);

#endif /* threads/fixed-point.h */
