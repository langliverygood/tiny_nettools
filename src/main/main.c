#include <stdio.h>
#include <pthread.h>

#include "lshell.h"
#include "sniffer.h"

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

void test_ls(int argc, char **argv)
{
	int i;
	
	printf("ls\n");
	printf("%d\n", argc);
	for(i = 0; i < argc; i++)
	{
		printf("%s\n", argv[i]);
	}
	
	return;
}

int main(int argc, char **argv)
{
	int ret;
	
	lshell_init();
	lshell_set_promt("tiny_nettools");
	lshell_set_errmsg_swtich(1);
	lshell_register(-1, "ls", "ls", test_ls, RUN_AT_NEW_THREAD);
	ret = lshell_register(-1, "sniffer", "sniffer", func_start_sniffer, RUN_AT_NEW_THREAD);
	lshell_register(ret, "stop", "sniffer stop", func_stop_sniffer, RUN_AT_NEW_THREAD);
	lshell_start();
		
	return 0;		
}
