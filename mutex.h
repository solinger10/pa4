#include "kernel.h"

//tries to "accquire" the lock, loops until obtained
void mutex_lock(int *lock);

//releases lock
void mutex_unlock(int *lock);

