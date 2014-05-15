#ifndef _NETWORK_H_
#define _NETWORK_H_

#include "kernel.h"

// Initializes teh network drive, allocating the space for the ring buffer.
void network_init();

// Starts receiving packets!
void network_start_receive();

// If opt != 0, enables interrupts when a new packet arrives.
// If opt == 0, disables interrupts.
void network_set_interrupts(int opt);

// Continually polls for data on the ring buffer. Loops forever!
void network_poll();

//called when a network interrupt occurs
void network_trap();

#endif
