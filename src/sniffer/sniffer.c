#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include "sniffer.h"

int sock;

char sniffer_init()
{
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
	{
		fprintf(stdout, "Create socket error, please try to run as an administrator\n");
		return 1;
	}
	
	return 0;
}

void sniffer_start()
{
        
	int n_read, proto;        
	char buffer[BUFFER_MAX];
	char  *ethhead, *iphead, *tcphead, *udphead, *icmphead, *p;
   
	while(1) 
	{
		n_read = recvfrom(sock, buffer, 2048, 0, NULL, NULL);
		/*
		14   6(dest)+6(source)+2(type or length)
		+
		20   ip header 
		+
		8   icmp,tcp or udp header
		= 42
		*/
		if(n_read < 42) 
		{
			fprintf(stdout, "Incomplete header, packet corrupt\n");
			continue;
		}
			
		ethhead = buffer;
		p = ethhead;
		printf("MAC: %.2X:%02X:%02X:%02X:%02X:%02X==>%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
					p[6] & 0XFF, p[7] & 0XFF, p[8] & 0XFF, p[9] & 0XFF, p[10] & 0XFF, p[11] & 0XFF,
					p[0] & 0XFF, p[1] & 0XFF, p[2] & 0XFF, p[3] & 0XFF, p[4] & 0XFF, p[5] & 0XFF);
		iphead = ethhead + 14;  
		p = iphead + 12;

		printf("IP: %d.%d.%d.%d => %d.%d.%d.%d\n",
				    p[0] & 0XFF, p[1] & 0XFF, p[2] & 0XFF, p[3] & 0XFF,
				    p[4] & 0XFF, p[5] & 0XFF, p[6] & 0XFF, p[7] & 0XFF);
		   
		proto = (iphead + 9)[0];
		p = iphead + 20;
		
		printf("Protocol: ");
		switch(proto)
		{
			case IPPROTO_ICMP: printf("ICMP\n");break;
			case IPPROTO_IGMP: printf("IGMP\n");break;
			case IPPROTO_IPIP: printf("IPIP\n");break;
			case IPPROTO_TCP :
			case IPPROTO_UDP : 
				printf("%s,", proto == IPPROTO_TCP ? "TCP": "UDP"); 
				printf("source port: %u,",(p[0]<<8)&0XFF00 |  p[1]&0XFF);
				printf("dest port: %u\n", (p[2]<<8)&0XFF00 | p[3]&0XFF);
				break;
			case IPPROTO_RAW : printf("RAW\n");break;
			default:printf("Unkown, please query in include/linux/in.h\n");
		}
		printf("\n");
	}
}
