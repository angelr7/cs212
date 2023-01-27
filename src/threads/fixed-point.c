#include "threads/thread.h"

int ready_threads_count;
int load_avg;


int calculate_priority(struct thread *t);
int calculate_recent_cpu(struct thread *t);
int calculate_load_avg(struct thread *t);

// priority, nice, and ready threads are ints
// recent_cpu and load_avg are real numbers
int calculate_priority(struct thread *t)
{
    return (PRI_MAX*(2 << 14) - (t->recent_cpu / 4) - (t->nice * 2)*(2 << 14))/(2 << 14);
}

int calculate_recent_cpu(struct thread *t)
{
    // turn this into ints
    int coefficient = ((int64_t)(2*load_avg))*(2 << 14)/(2*load_avg + 1*(2 << 14));
    return (((int64_t)coefficient) * t->recent_cpu / (2 << 14) + t->nice * (2 << 14))*100;
}

int calculate_load_avg(struct thread *t UNUSED)
{   
    // not sure if i can do list_size of fqs
    return (((int64_t) (59*(2 << 14)/60))*load_avg/(2 << 14) + (1*(2 << 14)/60)*ready_threads_count)*100;
}