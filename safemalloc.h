#include "kernel.h"

void init_safe_malloc();

void *malloc_safe(unsigned int size);

void free_safe(void *space);
