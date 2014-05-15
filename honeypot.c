#include "queue.h"
#include "kernel.h"


struct honeypot_command_packet *packet;

int total_packets;
int total_bytes;

void analyze() {
  packet = (struct honeypot_command_packet *)malloc(sizeof(struct honeypot_command_packet));
  while(1){
    if(queue_remove(packet)){
      //printf_m("read a packet for analysis!!!!!!!!\n");
      
      struct packet_header header = packet->headers;
      short packet_bytes = ((header.ip_len >> 8) | (header.ip_len << 8));
      
      //int hash = (int)djb2((unsigned char *)packet, header.ip_len);
      
      total_bytes += (int) packet_bytes;
      printf_m("bytes in packet: %d\n", packet_bytes);
      
      total_packets++;
      //printf_m("The secret is : %x\n",packet->secret_big_endian);
    }
  }
}

void print_stats() {
  printf_m("Total number of packets received: %d \n", total_packets);  
  printf_m("Total number of bytes received: %d \n", total_bytes);  
}
