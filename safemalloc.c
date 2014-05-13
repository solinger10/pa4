#include "mutex.h"

int *malloc_lock;
int *free_lock;

void init_safe_malloc() {
    malloc_lock = create_mutex();
    free_lock = create_mutex();
}

void *malloc_safe(unsigned int size) {
    mutex_lock(malloc_lock);
    void *free_space = malloc(size);
    mutex_unlock(malloc_lock);
    return free_space;
}

void free_safe(void *space) {
    mutex_lock(free_lock);
    free(space);
    mutex_unlock(free_lock);
}
