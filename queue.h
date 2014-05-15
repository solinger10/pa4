#ifndef QUEUE_H_
#define QUEUE_H_

#include "kernel.h"

#define Qsize 100

typedef struct tuple {
    struct honeypot_command_packet *packet;
    int length;
}tuple;

// adds the tuple to the end of the queue
int queue_add(struct tuple *x);

// creates a new empty queue
void initQueue();

// pops a tuple off the queue
int queue_remove(struct tuple *x);

#endif

