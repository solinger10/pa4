#define RING_SIZE NET_MAX_RING_CAPACITY
#define BUFFER_SIZE NET_MAXPKT

#include "network.h"
 

//a pointer to the memory-maped I/O region for the network card
volatile struct dev_net *network_dev;


void network_init(){
    // Find out where I/O region is in memory.
    for (int i = 0; i < 16; i++) {
  if (bootparams->devtable[i].type == DEV_TYPE_NETWORK) {
      puts("Detected network device...");
     
      // find a virtual address that maps to this I/O region
      network_dev = physical_to_virtual(bootparams->devtable[i].start);
      struct dma_ring_slot* ring = (struct dma_ring_slot*) malloc(sizeof(struct dma_ring_slot) * RING_SIZE);
     
      network_dev->rx_base = virtual_to_physical(ring);
      network_dev->rx_capacity = RING_SIZE;
      network_dev->rx_head = 0;
      network_dev->rx_tail = 0;
     
      for (int i = 0; i < RING_SIZE; ++i){
    void* space = malloc(BUFFER_SIZE);
    ring[i].dma_base = virtual_to_physical(space);
    ring[i].dma_len = BUFFER_SIZE;
      }
  }
    }
    puts("...device is ready!\n");
    return;
}
void network_start_receive() {
    // Turn on Device
    network_dev->cmd = NET_SET_POWER;
    network_dev->data = 1;

    // Start Receiving Packets
    network_dev->cmd = NET_SET_RECEIVE;
    network_dev->data = 1;

    return;
}

// If opt != 0, enables interrupts when a new packet arrives.
// If opt == 0, disables interrupts.
void network_set_interrupts(int opt) {
    network_dev->cmd = NET_SET_INTERRUPTS;
    network_dev->data = opt;
    set_cpu_status(current_cpu_status() | (1 << (8+INTR_NETWORK)));
}

//polls the buffer and "processes" the packets into the queue
void network_poll() {
  struct dma_ring_slot *ring = (struct dma_ring_slot *) physical_to_virtual(network_dev->rx_base);
  while(1){
    while(network_dev->rx_tail < network_dev->rx_head) {
      int index = network_dev->rx_tail % 16;
      //printf_m("rx_head: %d, rx_tail: %d, index: %d\n",network_dev->rx_head, network_dev->rx_tail, index);
      //printf_m("About to add to the queue\n");
      queue_add((struct honeypot_command_packet *)physical_to_virtual(ring[index].dma_base));
      //printf_m("Added to the queue\n");
      network_dev->rx_tail++;
    }
  }
}

void network_trap() {
  printf("A network interrrupt has occured \n");
  for (int i = 0; i<RING_SIZE; ++i){
      if (network_dev->rx_head != network_dev->rx_tail){
      unsigned int* ptr = (unsigned int *)physical_to_virtual(network_dev->rx_base);
      printf("ptr is: %p\n",ptr);
      printf("head is: %d, tail is: %d\n",network_dev->rx_head, network_dev->rx_tail);
      struct honeypot_command_packet* pkt =(struct honeypot_command_packet *) physical_to_virtual(ptr[network_dev->rx_head]);
      printf("The secret is : %x\n",pkt->secret_big_endian);
      }
  }
}
