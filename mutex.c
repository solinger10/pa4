#include "mutex.h"


int *create_mutex() {
    int *lock = malloc(sizeof(int));
    *lock = 0;
    return lock;
}

// The value stored in memory at the location pointed to by lock is
// 0 iff no other thread is using the corresponding data structure
// 1 otherwise
void mutex_lock(int *lock) {
  asm volatile (".set mips2");
  asm volatile ("1: li $8, 1" );
  asm volatile ("ll $9, 0($4)");
  asm volatile ("bnez $9, 1b");
  asm volatile ("nop");
  asm volatile ("sc $8, 0($4)");
  asm volatile ("beqz $8, 1b");
  asm volatile ("nop");
}


void mutex_unlock(int *lock) {
  *lock = 0;
}
