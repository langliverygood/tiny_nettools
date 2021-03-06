#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <errno.h>

#include "lshell.h"
#include "sniffer.h"
#include "arp.h"
#include "icmp_ping.h"
#include "syn_attack.h"

/***************************************************************/
/* 函  数：str_to_uint ******************************************/
/* 说  明：字符串转uint ******************************************/
/* 参  数：str 字符串 ********************************************/
/*        转换结果保存到n ****************************************/
/* 返回值：0 成功*************************************************/
/*        1 失败************************************************/
/**************************************************************/
static char str_to_long(const char *str, long int *n)
{
	long int val;
	char *endptr;
	
	errno = 0;
	val = strtol(str, &endptr, 0);
	if((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))|| (errno != 0 && val == 0)) 
	{
		return 1;
	}
	if(endptr == str) 
	{
	   return 1;
	}
	*n = val;
	
	return 0;
}

/***************************************************************/
/* 函  数：exec_sys_cmd *****************************************/
/* 说  明：执行系统命令 *******************************************/
/* 参  数：cmd 系统命令 ******************************************/
/*        flag 0 不输出终端的输入结构******************************/
/*             非0 输出 *****************************************/
/* 返回值：无 ***************************************************/
/**************************************************************/
static void exec_sys_cmd(const char *cmd, int flag)
{
	char buf[4096];
	int fd, cnt;
	FILE *fp; 
	
	fp = popen(cmd, "r"); 
	if(fp)
	{
		fd = fileno(fp); /* FILE结构体指针转成文件描述符 */
		cnt = read(fd, buf, sizeof(buf));
		if(flag)
		{
			write(1, buf, cnt);
		}
	}
	pclose(fp);
	
	return;
}

void sys_ifconfig(int argc, char **argv)
{
	exec_sys_cmd("ifconfig", 1);
	
	return;
}

/* arp deceive */
void func_arp_deceive(int argc, char **argv)
{
	if(argc < 3)
	{
		arp_usage();
		return;
	}
	if(argc > 3 && strcmp(argv[3], "-t") == 0)
	{
		arp_deceive(argv[0], argv[1], argv[2], 1);
	}
	else
	{
		arp_deceive(argv[0], argv[1], argv[2], 0);
	}
	
	return;
}

/* arp scan */
void func_arp_scan(int argc, char **argv)
{
	if(argc < 2)
	{
		arp_usage();
		return;
	}
	arp_scan(argv[0], argv[1]);
	
	return;
}

/* arp set deintvl */
void func_arp_set_deintvl(int argc, char **argv)
{
	long int n;
	
	if(str_to_long(argv[0], &n) == 0)
	{
		set_deceive_interval((int)n);
		return;
	}
	arp_usage();
	
	return;
}

/* arp set ptime */
void func_arp_set_rptime(int argc, char **argv)
{
	long int n;
	
	if(str_to_long(argv[0], &n) == 0)
	{
		set_scan_wait_time((int)n);;
		return;
	}
	arp_usage();
	
	return;
}

/* arp reset */
void func_arp_reset(int argc, char **argv)
{
	arp_reset();
	
	return;
}

/* arp help */
void func_arp_usage(int argc, char **argv)
{
	arp_usage();
	
	return;
}

/* sniffer start */
void func_start_sniffer(int argc, char **argv)
{
	if(sniffer_init() == 0)
	{
		sniffer_start();
	}
	
	return;
}

/* sniffer stop */
void func_stop_sniffer(int argc, char **argv)
{
	sniffer_stop();
	
	return;
}

/* sniffer help */
void func_sniffer_usage(int argc, char **argv)
{
	sniffer_usage();
	
	return;
}

/* ping start */
void func_start_ping(int argc, char **argv)
{
	long int n;
	
	if(argc < 1)
	{
		ping_usage();
		return;
	}
	else if(argc == 2)
	{
		if(str_to_long(argv[1], &n) == 0)
		{
			if(n == -1)
			{
				ping(argv[0], -1);
			}
			else if(n == 0)
			{
				ping(argv[0], 0);
			}
			else
			{
				ping(argv[0], (int)n);
			}
		}
		else
		{
			ping(argv[0], 0);
		}
	}
	else
	{
		ping(argv[0], 0);
	}
	
	return;
}

/* ping set times*/
void func_ping_set(int argc, char **argv)
{
	long int n;
	
	if(str_to_long(argv[0], &n) == 0)
	{
		set_ping_times((int)n);
		return;
	}
	arp_usage();
	
	return;
}
/* ping reset */
void func_ping_reset(int argc, char **argv)
{
	ping_reset();
	
	return;
}

/* ping help */
void func_ping_usage(int argc, char **argv)
{
	ping_usage();
	
	return;
}

/* syn attack */
void func_syn_attack(int argc, char **argv)
{
	long int target_port;
	long int local_port;
	
	if(argc == 3)
	{
		if(str_to_long(argv[1], &target_port) == 0 && str_to_long(argv[2], &local_port) == 0)
		{
			syn_attack(argv[0], (unsigned short)target_port, (unsigned short)local_port);
			return;
		}
	}
	syn_usage();
	
	return;
}

/* syn set interval*/
void func_syn_set(int argc, char **argv)
{
	long int n;
	
	if(str_to_long(argv[0], &n) == 0)
	{
		set_syn_interval_ms((int)n);
		return;
	}
	syn_usage();
	
	return;
}
/* syn reset */
void func_syn_reset(int argc, char **argv)
{
	syn_reset();
	
	return;
}

/* syn help */
void func_syn_usage(int argc, char **argv)
{
	syn_usage();
	
	return;
}

int main(int argc, char **argv)
{
	int ret;
	
	lshell_init();
	lshell_set_promt("tiny_nettools");
	lshell_set_errmsg_swtich(0);
	
	/* 系统命令 */
	lshell_register(-1, "ifconfig", "ifconfig", sys_ifconfig, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL); 
	/* arp */
	ret = lshell_register(-1, "arp", "arp", func_arp_usage, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL); 
	lshell_register(ret, "scan", "arp scan", func_arp_scan, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL); 
	lshell_register(ret, "deceive", "arp deceive", func_arp_deceive, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL); 
	lshell_register(ret, "set deintvl", "arp set", func_arp_set_deintvl, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL); 
	lshell_register(ret, "set rptime", "arp set", func_arp_set_rptime, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL); 
	lshell_register(ret, "reset", "arp reset", func_arp_reset, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL); 
	lshell_register(ret, "help", "arp help", func_arp_usage, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL); 
	/* sniffer */
	ret = lshell_register(-1, "sniffer", "sniffer", func_sniffer_usage, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL);
	lshell_register(ret, "start", "sniffer start", func_start_sniffer, RUN_AT_NEW_THREAD, DETACHED, CANSEL_ENABLE, CANSEL_EXIT_NOW);
	lshell_register(ret, "stop", "sniffer stop", func_stop_sniffer, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL);
	lshell_register(ret, "help", "sniffer help", func_sniffer_usage, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL);
	/* ping */
	ret = lshell_register(-1, "ping", "ping", func_start_ping, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL);
	lshell_register(ret, "set times", "set ping times", func_ping_set, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL);
	lshell_register(ret, "reset", "ping reset", func_ping_reset, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL);
	lshell_register(ret, "help", "ping help", func_ping_usage, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL);
	/* syn */
	ret = lshell_register(-1, "syn", "syn attack", func_syn_attack, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL);
	lshell_register(ret, "set intvl", "set syn interval", func_syn_set, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL);
	lshell_register(ret, "reset", "syn reset", func_syn_reset, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL);
	lshell_register(ret, "help", "syn help", func_syn_usage, RUN_AT_MAIN_THREAD, DEFAUL, DEFAUL, DEFAUL);
	/* 启动lshell */
	lshell_start();
		
	return 0;		
}
