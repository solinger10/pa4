#include "queue.h"

#define NULL ((void *)0)
#define PACKET_SIZE NET_MAXPKT

void queue_add(queue *a, struct honeypot_command_packet x) {
    // Adds the value x to the end of the queue
    if (a->buffer_size==0){
	a->buffer=(struct honeypot_command_packet *)malloc(PACKET_SIZE);
	if (a->buffer==0){return;}
	a->buffer_size=1;
    }
    if (a->length==a->buffer_size){
	a->buffer_size=2*a->buffer_size;
	// realloc
	struct honeypot_command_packet* temp = malloc(a->buffer_size*PACKET_SIZE);
	if (temp==0) {
	    printf("malloc failed");
	    return;
	}
	int i;
	for (i=0; i<a->length; i++) {
	    temp[i]=a->buffer[i];
	}
	free(a->buffer);
	a->buffer=temp;
    }
    a->buffer[a->length]=x;
    a->length+=1;
}

void queue_free(queue *a) {
    // freeing any memory used by that queue
    free(a->buffer);
    free(a);
}

queue* queue_new() {
    queue *a = (queue *)malloc(sizeof(queue));
    a->buffer=NULL;
    a->buffer_size = 0;
    a->length = 0;

    return a;
}

// removes the first item in the queue and shifts everything to the front
void queue_remove(queue *a) {
    int i;
    for(i = 0; i < a->length-1; i++)
        a->buffer[i] = a->buffer[i+1];
    
    --a->length; 
}
/*
struct honeypot_command_packet queue_get(queue *a, int index) {
    return(a->buffer[index]); 
}*/
/*
void queue_print(queue *a) {
    printf("[");
    if (a->length > 0) {
        int i;
        for(i = 0; i < a->length-1; i++)
            printf("%p, ",queue_get(a,i));
        printf("%p", queue_get(a,a->length-1));
    }

    printf("]\n");
}*/
