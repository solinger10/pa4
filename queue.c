// https://msmvps.com/blogs/vandooren/archive/2007/01/05/creating-a-thread-safe-producer-consumer-queue-in-c-without-using-locks.aspx
#include "queue.h"
#include "kernel.h"
#include "mutex.h"

volatile struct honeypot_command_packet *m_Data;
volatile int m_Read;
volatile int m_Write;
static int read_lock=0;

void initQueue() {
  m_Data = (struct honeypot_command_packet *)malloc(sizeof(struct honeypot_command_packet) * Qsize);
  m_Read = 0;
  m_Write = 0;
}

//only one core can call this
int queue_add(struct honeypot_command_packet *x)
{
  int nextElement = (m_Write + 1) % Qsize;
  if(nextElement != m_Read)
  {
    m_Data[m_Write] = *x;
    //free(x);
    m_Write = nextElement;
    return 1;
  }
  else{
    return 0;
  }
}

int queue_remove(struct honeypot_command_packet *x) {
  mutex_lock(&read_lock);
  if(m_Read == m_Write){
    mutex_unlock(&read_lock);
    return 0;
  }
  
  int nextElement = (m_Read + 1) % Qsize;
  *x = m_Data[m_Read];
  m_Read = nextElement;
  mutex_unlock(&read_lock);
  return 1;
}

