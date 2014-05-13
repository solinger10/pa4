#include "queue.h"
#include "kernel.h"


struct honeypot_command_packet *packet;

int total_packets;
int total_bytes;

void analyze() {
  packet = (struct honeypot_command_packet *)malloc(sizeof(struct honeypot_command_packet));
  while(1){
    if(queue_remove(packet)){
      printf_m("read a packet for analysis!!!!!!!!\n");
      total_packets++;
      printf_m("The secret is : %x\n",packet->secret_big_endian);
    }
  }
}

void print_stats() {
  printf_m("Total number of packets received: %d \n", total_packets);  
}
