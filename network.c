#include "network.h"
#include "kernel.h"

#define RING_SIZE 16
#define BUFFER_SIZE 1024

volatile struct dev_net *dev_net;

void network_init(){
  for (int j = 0; j < 16; j++) {
    if (bootparams->devtable[j].type == DEV_TYPE_NETWORK) {
      puts("Detected network device...\n");
      struct dma_ring_slot* ring = (struct dma_ring_slot*) malloc(sizeof(struct dma_ring_slot) * RING_SIZE);
      dev_net = physical_to_virtual(bootparams->devtable[j].start);
      dev_net->rx_base = virtual_to_physical(ring);
      dev_net->rx_capacity = RING_SIZE;
      dev_net->rx_tail = 0;
      dev_net->rx_head = 0;
    
      for (int i = 0; i < RING_SIZE; ++i) {
        void* space = malloc(BUFFER_SIZE);
        ring[i].dma_base = virtual_to_physical(space);
        ring[i].dma_len = BUFFER_SIZE;
      }
  
      puts("...network driver is ready.\n");
      return;
    }
  }
}

void network_set_interrupts(int opt){
  dev_net->cmd = NET_SET_INTERRUPTS;
  dev_net->data = opt;
  
  // also allow network interrupts
  set_cpu_status(current_cpu_status() | (1 << (8+INTR_NETWORK)));
}

void network_start_receive(){
  dev_net->cmd = NET_SET_POWER;
  dev_net->data = 1;
  dev_net->cmd = NET_SET_RECEIVE;
  dev_net->data = 1;
}

void handle_packet(){
  puts("I got a packet!\n");
}

void network_trap() {
  handle_packet();
}

void network_poll() {
  while (1) {
    while(dev_net->rx_tail < dev_net->rx_head) {
      handle_packet();
      dev_net->rx_tail++;
    }
  }
}

