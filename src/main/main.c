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

/***************************************************************/
/* 函  数：str_to_uint ******************************************/
/* 说  明：字符串转uint ******************************************/
/* 参  数：str 字符串 ********************************************/
/*        转换结果保存到n ****************************************/
/*             非0 输出 ****************************************/
/* 返回值：0 成功*************************************************/
/*        1 失败************************************************/
/**************************************************************/
static char str_to_uint(const char *str, unsigned int *n)
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
	
	*n = (int)val;
	
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

/* arp set */
void func_arp_set(int argc, char **argv)
{
	unsigned int n;
	
	if(str_to_uint(argv[1], &n) == 0)
	{
		if(strcmp(argv[0], "deintvl") == 0)
		{
			set_deceive_interval(n);
		}
		else if(strcmp(argv[0], "rptime") == 0)
		{
			set_scan_wait_time(n);
		}
		else
		{
			arp_usage();
		}
	}
	else
	{
		arp_usage();
	}
	
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

int main(int argc, char **argv)
{
	int ret;
	
	lshell_init();
	lshell_set_promt("tiny_nettools");
	lshell_set_errmsg_swtich(0);
	
	/* 系统命令 */
	lshell_register(-1, "ifconfig", "ifconfig", sys_ifconfig, RUN_AT_MAIN_THREAD, 0, 0, 0); 
	/* arp */
	ret = lshell_register(-1, "arp", "arp", func_arp_usage, RUN_AT_MAIN_THREAD, 0, 0, 0); 
	lshell_register(ret, "scan", "arp scan", func_arp_scan, RUN_AT_MAIN_THREAD, 0, 0, 0); 
	lshell_register(ret, "deceive", "arp deceive", func_arp_deceive, RUN_AT_MAIN_THREAD, 0, 0, 0); 
	lshell_register(ret, "set", "arp set", func_arp_set, RUN_AT_MAIN_THREAD, 0, 0, 0); 
	lshell_register(ret, "reset", "arp reset", func_arp_reset, RUN_AT_MAIN_THREAD, 0, 0, 0); 
	lshell_register(ret, "help", "arp help", func_arp_usage, RUN_AT_MAIN_THREAD, 0, 0, 0); 
	/* sniffer */
	ret = lshell_register(-1, "sniffer", "sniffer", func_sniffer_usage, RUN_AT_NEW_THREAD, 0, 0, 0);
	lshell_register(ret, "start", "sniffer start", func_start_sniffer, RUN_AT_NEW_THREAD, 1, 0, 1);
	lshell_register(ret, "stop", "sniffer stop", func_stop_sniffer, RUN_AT_MAIN_THREAD, 0, 0, 0);
	lshell_register(ret, "help", "sniffer help", func_sniffer_usage, RUN_AT_MAIN_THREAD, 0, 0, 0);
	
	/* 启动lshell */
	lshell_start();
		
	return 0;		
}
