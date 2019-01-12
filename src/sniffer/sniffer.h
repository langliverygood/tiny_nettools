#ifndef _SNIFFER_H_
#define _SNIFFER_H_

#define BUFFER_MAX 2048
#define RING_BUFFER_SIZE 127
#define PACP_MAX_NUM 100

char sniffer_init();
void sniffer_start();
void sniffer_stop();


#endif
