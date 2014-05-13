#ifndef _QUEUE_H_
#define _QUEUE_H_

#include "kernel.h"

typedef struct queue {
    struct honeypot_command_packet *buffer; // pointer to allocated memory
    int buffer_size; // the max number of packets the queue can hold
    int length; // the number of packets in the queue
}queue;

// adds the packet to the end of the queue
void queue_add(queue *a, struct honeypot_command_packet x);

// frees any memory used by the queue
void queue_free(queue *a);

// creates a new empty
queue* queue_new();

// removes the item at the front (index 0) of the queue
// and shifts everything else up
void queue_remove(queue *a);

// returns the packet at the specified index
//struct honeypot_command_packet queue_get(queue *a, int index);

#endif
