#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "lshell.h"
#include "sniffer.h"
#include "arp.h"

void func_arp_deceive(int argc, char **argv)
{
	arp_deceive(argv[0], argv[1], argv[2], 0);
	
	return;
}

void func_start_sniffer(int argc, char **argv)
{
	if(sniffer_init() == 0)
	{
		sniffer_start();
	}
	
	return;
}

void func_stop_sniffer(int argc, char **argv)
{
	sniffer_stop();
	
	return;
}

void run_ifconfig(int argc, char **argv)
{
	char buf[4096];
	int fd, cnt;
	FILE *fp; 
	
	fp = popen("ifconfig", "r"); 
	if(fp)
	{
		fd = fileno(fp);
		cnt = read(fd, buf, sizeof(buf));
		write(1, buf, cnt);
	}
	pclose(fp);
	
	
	return;
}

int main(int argc, char **argv)
{
	int ret;
	
	lshell_init();
	lshell_set_promt("tiny_nettools");
	lshell_set_errmsg_swtich(1);
	lshell_register(-1, "ifconfig", "ifconfig", run_ifconfig, RUN_AT_MAIN_THREAD);
	lshell_register(-1, "arp", "arp", func_arp_deceive, RUN_AT_MAIN_THREAD);
	ret = lshell_register(-1, "sniffer", "sniffer", func_start_sniffer, RUN_AT_NEW_THREAD);
	lshell_register(ret, "stop", "sniffer stop", func_stop_sniffer, RUN_AT_NEW_THREAD);
	lshell_start();
		
	return 0;		
}
