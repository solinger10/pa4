#include "network.h"
#include "kernel.h"

#define RING_SIZE 16
#define BUFFER_SIZE 1024

volatile struct dev_net *dev_net;

network_init(){
  if (bootparams->devtable[i].type == DEV_TYPE_NETWORK) {
    puts("Detected network device...\n");
    struct dma_ring_slot* ring = (struct dma_ring_slot*) malloc(sizeof(struct dma_ring_slot) * RING_SIZE);
    dev_net = physical_to_virtual(bootparams->devtable[i].start);
    dev_net->rx_base = virtual_to_physical((void *) ring);
    dev_net->rx_capacity = RING_SIZE;
    dev_net->rx_tail = 0;
    dev_net->rx_head = 0;
    
    for (int i = 0; i < RING_SIZE; ++i) {
      void* space = malloc(BUFFER_SIZE);
      ring[i].dma_base = /* you figure this part out! */;
      ring[i].dma_len = /* you figure this part out! */;
    }

    puts("...network driver is ready.\n");
    return;
  }
}

network_set_interrupts(1){
  
}

network_start_receive(){
  dev_net->cmd = NET_SET_POWER;
  dev_net->data = 1;
  dev_net->cmd = NET_SET_RECEIVE;
  dev_net->data = 1;
}