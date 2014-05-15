#include "mutex.h"
#include "hashtable.h"
#include "queue.h"
#include "kernel.h"

struct honeypot_command_packet *packet;

//key = source addr of spammer, value = # of packets received from spammer
struct HashTable *spammer_table;
//key = vulnerable destination port, valu = # of packets w/ this destination
struct HashTable *vulnerable_table;
//key = hash of evil_packet, value = # of packets that hash to this key
struct HashTable *evil_table;

static int spammer_table_lock = 0;
static int vulnerable_table_lock = 0;
static int evil_table_lock = 0;

int total_packets;
int total_bytes;

void initialize_honeypot() {
  printf("initializing honeypot\n");
  spammer_table = hashtable_create(HASHTABLE_SIZE);
  vulnerable_table = hashtable_create(HASHTABLE_SIZE);
  evil_table = hashtable_create(HASHTABLE_SIZE);
}

void analyze() {
  if (current_cpu_id() == 0) {
    //initialize_honeypot();
  }
  packet = (struct honeypot_command_packet *)malloc(sizeof(struct honeypot_command_packet));
  while(1){
    if(queue_remove(packet)){
      //printf_m("Core %d removed a packet!\n", current_cpu_id());
      unsigned short packet_bytes = big_to_little_short(packet->headers.ip_len);
      //printf_m("packet size: %d\n",packet_bytes);
      if (big_to_little_short(packet->secret_big_endian) == HONEYPOT_SECRET) {
	//printf_m("Core %d removed a command packet!\n", current_cpu_id());
	handle_command(packet);
      }
      else {
	//printf_m("Core %d removed a regular packet!\n", current_cpu_id());
        handle_regular(packet, packet_bytes);
      }
      //printf_m("read a packet for analysis!!!!!!!!\n");
      total_packets++;
      total_bytes += packet_bytes;
      //printf_m("The secret is : %x\n",packet->secret_big_endian);
    }
  }
}

void print_stats() {
  int total_cycles = current_cpu_cycles();
  int total_time = total_cycles * CPU_CYCLES_PER_SECOND;
  printf_m("Total number of packets received: %d \n", total_packets); 
  printf_m("Total number of bytes received: %d \n", total_bytes);
  printf_m("Total time is: %d\n",total_time);
  printf_m("Packets per second: %d\n",total_packets/(float)total_time);
  printf_m("Bytes per second: %d\n",total_bytes/(float)total_time);
  printf_m("Printing spammer source addresses: \n");
  hashtable_print(spammer_table);
  printf_m("Printing vulnerable ports: \n");
  hashtable_print(vulnerable_table);
  printf_m("Printing evil packets: \n");
  hashtable_print(evil_table);
  busy_wait(4.0);
}

void handle_command(struct honeypot_command_packet *cmd_packet) {
  unsigned short cmd = big_to_little_short(cmd_packet->cmd_big_endian);
  unsigned int data = big_to_little_int(cmd_packet->data_big_endian);
  unsigned short sdata = (unsigned short)big_to_little_int(cmd_packet->data_big_endian);
  //printf_m("core %d sees sdata is %x\n",current_cpu_id(), sdata);
  //printf_m("core %d sees real data is %x\n",current_cpu_id(),cmd_packet->data_big_endian);
  switch (cmd) {
    case HONEYPOT_ADD_SPAMMER:
      mutex_lock(&spammer_table_lock);
      hashtable_put(spammer_table,(int)data, 0);
      mutex_unlock(&spammer_table_lock);
      break;
    case HONEYPOT_ADD_EVIL:
      //printf_m("hash that we are looking for is: %x\n",(int)data);
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
  //printf_m("Core %d is processing a regular packet!\n", current_cpu_id());
  struct packet_header *header = &reg_packet->headers;
  //printf_m("Core %d is computing source!\n", current_cpu_id());
  unsigned int source = big_to_little_int(header->ip_source_address_big_endian);
  //printf_m("Core %d is computing dest!\n", current_cpu_id());
  unsigned short dest = big_to_little_short(header->udp_dest_port_big_endian);
  //printf_m("Core %d is computing djb2!\n", current_cpu_id());
  int hash = djb2((unsigned char *)reg_packet, (int)packet_len);
  printf_m("first core %d sees hash as %x\n", current_cpu_id(),hash);
  hash = (int)big_to_little_int((unsigned int)hash);
  printf_m("now core %d sees hash as %x\n", current_cpu_id(),hash);
  //printf_m("hash is %x\n", hash);
  //printf_m("Core %d has source = %d, dest = %d, hash = %d\n", current_cpu_id(), source, dest, hash);
  int source_val = hashtable_contains(spammer_table, (long)source);
  int vulnerable_val = hashtable_contains(vulnerable_table, (long)dest);
  int evil_val = hashtable_contains(evil_table, (long)hash);
  //printf_m("Core %d is finished with inits!\n", current_cpu_id());
  if (source_val != -1) {
    //printf_m("Core %d removed a spammer packet!\n", current_cpu_id());
    source_val++;
    mutex_lock(&spammer_table_lock);
    hashtable_remove(spammer_table, source);
    hashtable_put(spammer_table, source, source_val);
    mutex_unlock(&spammer_table_lock);
  }
  if (vulnerable_val != -1){
    //printf_m("Core %d removed a vulnerable packet!\n", current_cpu_id());
    vulnerable_val++;
    mutex_lock(&vulnerable_table_lock);
    hashtable_remove(vulnerable_table, dest);
    hashtable_put(vulnerable_table, dest, vulnerable_val);
    mutex_unlock(&vulnerable_table_lock);
  }
  if (evil_val != -1){
    //printf_m("Core %d removed a evil packet!\n", current_cpu_id());
    evil_val++;
    //printf_m("hash is: %d\n",hash);
    //busy_wait(1.0);
    mutex_lock(&evil_table_lock);
    hashtable_remove(evil_table, hash);
    hashtable_put(evil_table, dest, evil_val);
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

unsigned long djb2(unsigned char *pkt, int n)
{
  //printf_m("core %d sees length n as %d\n",current_cpu_id(),n);
  unsigned long hash = 5381;
  int c;
  for (int i = 0; i<n; i++) {
    c = pkt[i];
    hash = hash*33 + c;
    //hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  }
  return hash;
}
