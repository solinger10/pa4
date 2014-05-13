#include "mutex.h"

// The value stored in memory at the location pointed to by lock is
// 0 iff no other thread is using the corresponding data structure
// 1 otherwise
void mutex_lock(unsigned int *lock) {
  asm volatile (".set mips2");
  asm volatile ("1: li $8, 1" );
  asm volatile ("ll $9, 0($4)");
  asm volatile ("bnez $9, 1b");
  asm volatile ("nop");
  asm volatile ("sc $8, 0($4)");
  asm volatile ("beqz $8, 1b");
  asm volatile ("nop");
  
}


void mutex_unlock(unsigned int *lock) {
  asm volatile ("sw $0, 0($4)");
}

void mutex_test() {
  /*
  unsigned int count = 0;
  unsigned int count_lock=0;
  */unsigned int print_lock = 0;
  int cpu_id = current_cpu_id();
  /*while (count < 1000) {
    mutex_lock(&print_lock);
    printf("Core %d is going to try to get the lock...\n",cpu_id);
    mutex_unlock(&print_lock);
    mutex_lock(&count_lock);
    mutex_lock(&print_lock);
    printf("... Core %d got the lock!\n",cpu_id);
    printf("Core %d is about to increment count...\n",cpu_id);
    printf("count was %d ...",count);
    mutex_unlock(&print_lock);
    count += 1;
    mutex_lock(&print_lock);
    printf("... now, count is %d ...",count);
    printf("... Core %d incremented count!",cpu_id);
    printf("Core %d is going to release the lock... \n",cpu_id);
    mutex_unlock(&print_lock);
    mutex_unlock(&count_lock);
    mutex_lock(&print_lock);
    printf("... Core %d released the lock!\n", cpu_id);
    mutex_unlock(&print_lock);
  }*/
  mutex_lock(&print_lock);
  printf("Core %d has reached the end of the loop.\n",cpu_id);
  mutex_unlock(&print_lock);
}
