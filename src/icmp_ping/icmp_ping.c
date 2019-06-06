#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>

#include "print.h"
#include "icmp_ping.h"

static int ping_sock_fd;                  /* pind的原始套接字标识符 */
static char sock_exsit;                   /* ping套接字是否建立 */         
static unsigned int ping_times = 4;       /* ping 默认次数*/
static char flag_stop;                    /* 停止ping的标志 */
static char request_pkt[REQUEST_PKT_LEN]; /* ping请求包 */
static char resonse_pkt[RESONSE_PKT_LEN]; /* ping响应包*/

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
/* 函  数：ping_init ********************************************/
/* 说  明：初始化ping的一些参数 ************************************/
/* 参  数：无 ***************************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
static void ping_init()
{
	struct icmp *icmp;
	struct timeval tv_out;
	
	if(!sock_exsit)
	{
		ping_sock_fd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
		if(ping_sock_fd < 0)
		{
			print_errno("%s", "Failed to create ping socket!");
			return;
		}
		sock_exsit = 1;
		icmp = (struct icmp*)request_pkt;
		icmp->icmp_type = 8;
		icmp->icmp_code = 0;
		icmp->icmp_id = getpid() & 0xffff; /* 线程号作为id */
		tv_out.tv_sec = 1;
		tv_out.tv_usec = 0;
		setsockopt(ping_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)); /* recv超时时间为1s */
	}
	
	return;
}

/***************************************************************/
/* 函  数：ping_clear *******************************************/
/* 说  明：释放ping占用的系统资源 **********************************/
/* 参  数：无 ***************************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
static void ping_clear()
{
	if(sock_exsit)
	{
		sock_exsit = 0;
		close(ping_sock_fd);
	}
	flag_stop = 0;
	signal(SIGINT, SIG_DFL);
	
	return;
}

/***************************************************************/
/* 函  数：calc_cksum *******************************************/
/* 说  明：计算校验和 ********************************************/
/* 参  数：buff包的首地址 ****************************************/
/*        len包的长度********************************************/
/* 返回值：校验和 ************************************************/
/**************************************************************/
static unsigned short calc_cksum(char *buff, int len)
{
    unsigned short *mid;
    unsigned short te = 0;
    unsigned int sum;;
    
    mid = (unsigned short*)buff;
    sum = 0;
    while(len > 1)
    {
       sum += *mid++;
       len -= 2; 
    }
    
    /* 如果奇数个字节，将多出的一字节放入short类型的高位,低8位置0,加入到sum中 */ 	
    if(len == 1)
    {  
       te = *(unsigned char*)mid;
       te  = (te << 8) & 0xff;
       sum += te;                
    }
    sum = (sum >> 16) + (sum & 0xffff); 
    sum += sum >> 16;
    
    return (unsigned short)(~sum);
}

/***************************************************************/
/* 函  数：fill_packet ******************************************/
/* 说  明：填充ping请求包 *****************************************/
/* 参  数：buff包的首地址 *****************************************/
/*        len包的长度 ********************************************/
/*        请求包的序列号******************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
static void fill_packet(char *buff, int len, int seq)
{
    struct timeval *tval;
    struct icmp *icmp;
    
    icmp = (struct icmp*)request_pkt;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = seq;
    tval = (struct timeval *)icmp->icmp_data;    
    gettimeofday(tval, NULL);                 /* 获得传输时间作为数据 */
    icmp->icmp_cksum = calc_cksum(buff, len); /* 计算校验和 */
      
    return;    
}

/***************************************************************/
/* 函  数：parse_packet *****************************************/
/* 说  明：解析ping回应包 *****************************************/
/* 参  数：buff包的首地址 *****************************************/
/*        len包的长度 *******************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
static void parse_packet(char *buff, int len)
{
	double usec;
    struct timeval *val;
    struct timeval now;
    struct icmp *icmp;
    struct iphdr *iphead;
    struct in_addr addr;
    
    iphead = (struct iphdr *)buff;
    addr.s_addr = iphead->saddr;
    printf("Reply from ip=%s", inet_ntoa(addr));
    /* 跳过ip头 */
    icmp = (struct icmp *)(buff + sizeof(struct iphdr));
    /* 看传输回的包校验和是否正确 */
    if(calc_cksum((char *)icmp,len-sizeof(sizeof(struct iphdr))) > 1)
    {
       printf("There was an error in the ping packet received\n");
       return;
    } 
    
    gettimeofday(&now, NULL);
    val = (struct timeval *)icmp->icmp_data;
    usec = (double)(now.tv_usec - val->tv_usec) / 1000;
    printf("  seq=%d  id=%d  usec=%.3lfms\n" ,icmp->icmp_seq, icmp->icmp_id, usec);
    
    return; 
}

/***************************************************************/
/* 函  数：ping *************************************************/
/* 说  明：ping的主程序 ******************************************/
/* 参  数：target：ip，也可以是主机名或域名 *************************/
/*      ：times = -1 一直请求 ***********************************/
/*      ：times = 0 默认请求次数 *********************************/
/*      ：times = 其他请他请求次数 ********************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void ping(char *target, int times)
{
    int ret, cnt, seq;
    struct sockaddr_in sender;
    struct in_addr inaddr_tmp;
    struct icmp *icmp;
    struct hostent* host; 
	
    /* 参数检查 */
    if(inet_aton(target, &inaddr_tmp) == 0)
    {
        /* 获取IP地址的主机名，攻击使用第一个IP */
        host = gethostbyname(target);
        if(host == NULL)
        { 
			print_error("%s", "gethostbyname fail!\n");
			return;
		}
		inaddr_tmp = *(struct in_addr*)(host->h_addr_list[0]);
	}
	
	ping_init();
	memset(&sender, 0, sizeof(sender));
    sender.sin_family = AF_INET;
    sender.sin_addr.s_addr = inaddr_tmp.s_addr;
    
	/* 每一秒发送一次 共发送cnt次 */    
	seq = 1;
	if(times == -1)
	{
		cnt = 1;
		printf("Ping requests will always be sent！\n");
	}
	else if(times == 0)
	{
		cnt = ping_times;
		printf("Ping requests will be sent %d times！\n", cnt);
	}
	else
	{
		cnt = times;
		printf("Ping requests will be sent %d times！\n", cnt);
		if(cnt < 0)
		{
			printf("Parameter (times) Error!\n");
			return;
		}
	}
	
	/* 跳过ip头 */
	icmp = (struct icmp *)(resonse_pkt + sizeof(struct iphdr));
	signal(SIGINT, sig_int);
	while(cnt > 0)
	{
		if(flag_stop)
		{
			ping_clear();
			return;
		}
		
		fill_packet(request_pkt, REQUEST_PKT_LEN, seq);
		seq++;
		if(times != -1)
		{
			cnt--;
		}

		/* 发送ping */
		ret = sendto(ping_sock_fd, request_pkt, sizeof(request_pkt), 0, (struct sockaddr *)&sender, sizeof(sender)); 
		if(ret <= 0)
		{
			print_errno("Failed to send ping packet!\n"); 
			ping_clear();
			return;
		}  
		else
		{
			//printf("send %d bytes!\n", ret);
		}

		/* 接收ping回应 */
		memset(resonse_pkt, 0, sizeof(resonse_pkt));
		ret = recvfrom(ping_sock_fd, resonse_pkt, sizeof(resonse_pkt), 0, NULL, NULL);     
		if(ret <= 0)
		{
			print_errno("Failed to receive ping packet!\n");
			ping_clear();
			return;
		}
		if(icmp->icmp_type == 0)
		{
			parse_packet(resonse_pkt, ret);
		}
		else
		{
			printf("Reply packet lost!\n");
		}
		
		sleep(1);
	}
    ping_clear();
    
    return;
}

/***************************************************************/
/* 函  数：ping_reset *******************************************/
/* 说  明：恢复ping的一些默认参数 **********************************/
/* 参  数：无 ***************************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void ping_reset()
{
	set_ping_times(4);
	
	return;
}

/***************************************************************/
/* 函  数：set_ping_times ***************************************/
/* 说  明：设置ping的默认次数 *************************************/
/* 参  数：times 次数 ********************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void set_ping_times(int times)
{
	if(times < 0)
	{
		printf("Patameter error!(%d)\n", times);
		return;
	}
	ping_times = times;
	printf("Default ping times was set to %d!\n", times);
	
	return;
}

/***************************************************************/
/* 函  数：ping_usage *******************************************/
/* 说  明：介绍ping使用方法 ***************************************/
/* 参  数：无 ***************************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void ping_usage()
{
	printf("\n[Ping Usage]\n\n");
	printf("--\"Ping [ip 、hostname or domain] (n)\" :Ping requests will be sent n times！ " 
	    "When n = 0 or missing, ping requests will be sent default times！ "
	    "When n = -1, ping requests will be always sent\n\n");
	printf("--\"ping set times [n]\" :Default times of ping requests will be set to n.\n\n");
	printf("--\"ping reset\" :When you use this command, some parameters of ping will be restored.\n\n");
	printf("--\"ping help\":Show this explanation.\n\n");
	
	return;
}
