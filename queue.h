
#include "kernel.h"

#define Qsize 500

// adds the packet to the end of the queue
int queue_add(struct honeypot_command_packet *x);

// creates a new empty queue
void initQueue();

// pops a packet off the queue
int queue_remove(struct honeypot_command_packet **x);

