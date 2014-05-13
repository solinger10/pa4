#ifndef _NETWORK_H_
#define _NETWORK_H_

#include "kernel.h"

void mutex_lock(unsigned int *lock);

void mutex_unlock(unsigned int *lock);

void mutex_test();
#endif
