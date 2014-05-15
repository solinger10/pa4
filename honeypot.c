#include "mutex.h"
#include "hashtable.h"
#include "queue.h"
#include "kernel.h"

//struct honeypot_command_packet *packet;

//key = source addr of spammer, value = # of packets received from spammer
struct HashTable *spammer_table;
//key = vulnerable destination port, valu = # of packets w/ this destination
struct HashTable *vulnerable_table;
//key = hash of evil_packet, value = # of packets that hash to this key
struct HashTable *evil_table;

static int spammer_table_lock = 0;
static int vulnerable_table_lock = 0;
static int evil_table_lock = 0;

unsigned int start_cycles;
unsigned int total_packets;
unsigned int total_bytes;

// 1 iff the honeypot has been initialized and can print statistics
static int can_print = 0;

void initialize_honeypot() {
  spammer_table = hashtable_create(HASHTABLE_SIZE);
  vulnerable_table = hashtable_create(HASHTABLE_SIZE);
  evil_table = hashtable_create(HASHTABLE_SIZE);
  start_cycles = current_cpu_cycles();
  can_print = 1;
  
}

void analyze() {
  struct honeypot_command_packet **packet = (struct honeypot_command_packet **)malloc(NET_MAXPKT);
  while(1){
    //if queue is not empty, remove a packet
    if(queue_remove(packet)){
      struct honeypot_command_packet *ptr = (struct honeypot_command_packet *)*packet;
      //length of packet
      unsigned short packet_bytes = big_to_little_short(ptr->headers.ip_len);
      //handle command packets accordingly
      if (big_to_little_short(ptr->secret_big_endian) == HONEYPOT_SECRET) {
	handle_command(ptr);
      }
      else {
        handle_regular(ptr, packet_bytes);
      }
      //update global stats
      total_packets++;
      total_bytes += packet_bytes;
    }
  }
}

void print_stats() {
  if (can_print)
  {
  unsigned int total_cycles = current_cpu_cycles();
  int total_time = (total_cycles - start_cycles)/ CPU_CYCLES_PER_SECOND;
  printf_m("Total number of packets received: %u packets\n", total_packets); 
  printf_m("Total number of bytes received: %u bytes\n", total_bytes);
  if (total_time == 0) {
    printf_m("not enough time has elapsed for full statistics\n");
  }
  else {
    printf_m("Total time is: %u seconds\n",total_time);
    printf_m("Packets per second: %u\n",total_packets/total_time);
    printf_m("MBits per second: %u\n",total_bytes*8/(1000000*total_time));
  }
  printf_m("Printing spammer source addresses:  \n");
  printf_m("Key = source address; Value = # of packets from this address \n");
  hashtable_print(spammer_table);
  printf_m("Printing vulnerable ports: \n");
  printf_m("Key = destination port; Value = # of packets w/ this destination port \n");
  hashtable_print(vulnerable_table);
  printf_m("Printing evil packets: \n");
  printf_m("Key = djb2 hash value; Value = # of packets with this hash \n");
  hashtable_print(evil_table);
  busy_wait(4.0);
  }
  else printf_m("Cannot print stats: Honeypot not yet initialized\n");
}

void handle_command(struct honeypot_command_packet *cmd_packet) {
  //command entry in honeypot packet converted to little endian
  unsigned short cmd = big_to_little_short(cmd_packet->cmd_big_endian);
  //data entry in honeypot packet converted to little endian
  unsigned int data = big_to_little_int(cmd_packet->data_big_endian);
  //same as data but casted to two bytes (short)
  unsigned short sdata = (unsigned short)big_to_little_int(cmd_packet->data_big_endian);
  switch (cmd) {
    case HONEYPOT_ADD_SPAMMER:
      mutex_lock(&spammer_table_lock);
      hashtable_put(spammer_table,(int)data, 0);
      mutex_unlock(&spammer_table_lock);
      break;
    case HONEYPOT_ADD_EVIL:
      mutex_lock(&evil_table_lock);
      hashtable_put(evil_table, (int)data, 0);
      mutex_unlock(&evil_table_lock);
      break;
    case HONEYPOT_ADD_VULNERABLE:
      mutex_lock(&vulnerable_table_lock);
      hashtable_put(vulnerable_table, (int)sdata, 0);
      mutex_unlock(&vulnerable_table_lock);
      break;
    case HONEYPOT_DEL_SPAMMER:
      mutex_lock(&spammer_table_lock);
      hashtable_remove(spammer_table, (int)data);
      mutex_unlock(&spammer_table_lock);
      break;
    case HONEYPOT_DEL_EVIL:
      mutex_lock(&evil_table_lock);
      hashtable_remove(evil_table, (int)data);
      mutex_unlock(&evil_table_lock);
      break;
    case HONEYPOT_DEL_VULNERABLE:
      mutex_lock(&vulnerable_table_lock);
      hashtable_remove(vulnerable_table, (int)sdata);
      mutex_unlock(&vulnerable_table_lock);
      break;
    case HONEYPOT_PRINT:
      print_stats();
      break;
  }
}

void handle_regular(struct honeypot_command_packet *reg_packet, unsigned short packet_len) {
  //get source address, destination port, and complete djb2 hash value
  struct packet_header *header = &reg_packet->headers;
  unsigned int source = big_to_little_int(header->ip_source_address_big_endian);
  unsigned short dest = big_to_little_short(header->udp_dest_port_big_endian);
  int hash = djb2((unsigned char *)reg_packet, (int)packet_len);
  // each of the *_val variables are -1 if their respective hashtable does not contain the source/dest/hash
  // and are equal to the value of the corresponding hashtable entry otherwise
  int source_val = hashtable_contains(spammer_table, (long)source);
  int vulnerable_val = hashtable_contains(vulnerable_table, (long)dest);
  int evil_val = hashtable_contains(evil_table, (long)hash);
  if (source_val != -1) {
    mutex_lock(&spammer_table_lock);
    source_val++;
    hashtable_remove(spammer_table, source);
    hashtable_put(spammer_table, source, source_val);
    mutex_unlock(&spammer_table_lock);
  }
  if (vulnerable_val != -1){
    mutex_lock(&vulnerable_table_lock);
    vulnerable_val++;
    hashtable_remove(vulnerable_table, dest);
    hashtable_put(vulnerable_table, dest, vulnerable_val);
    mutex_unlock(&vulnerable_table_lock);
  }
  if (evil_val != -1){
    mutex_lock(&evil_table_lock);
    evil_val++;
    hashtable_remove(evil_table, hash);
    hashtable_put(evil_table, hash, evil_val);
    mutex_unlock(&evil_table_lock);
  }
}
// big-to-little endian funtions taken from http://stackoverflow.com/questions/2182002/convert-big-endian-to-little-endian-in-c-without-using-provided-func

unsigned short big_to_little_short(unsigned short val){
  return (val << 8) | (val >> 8);
}

unsigned int big_to_little_int(unsigned int val) {
  val = ((val << 8) & 0xff00ff00) | ((val >> 8) & 0xff00ff);
  return (val << 16) | (val >> 16);
}

//djb2, slightly optimized from the version posted on the CS3410 pa4 FAQ page
unsigned long djb2(unsigned char *pkt, int n)
{
  unsigned long hash = 5381;
  int i = 0;
  while (i < n-28) {
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
     hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
    hash = hash * 33 + pkt[i++];
  }
  while (i < n)
    hash = hash * 33 + pkt[i++];
  return hash;
}
