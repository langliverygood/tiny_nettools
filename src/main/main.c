#include <stdio.h>
#include <pthread.h>

#include "lshell.h"
#include "sniffer.h"

static pthread_t sniffer_td;

void *thread_sniffer()
{
	if(sniffer_init() == 0)
	{
		sniffer_start();
	}
	
	return NULL;
}

void func_start_sniffer(int argc, char **argv)
{
	int ret;
	
	ret = pthread_create(&sniffer_td, NULL, thread_sniffer, NULL);
	
	if(ret != 0)
	{
		printf("Sniffer thread failed to start!\n");
		return;
	}
	
	return;
}

void func_stop_sniffer(int argc, char **argv)
{
	pthread_cancel(sniffer_td);
	
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
	lshell_set_promt("ex");
	lshell_set_errmsg_swtich(1);
	lshell_register(-1, "ls", "ls", test_ls);
	ret = lshell_register(-1, "sniffer", "sniffer", func_start_sniffer);
	lshell_register(ret, "stop", "sniffer stop", func_stop_sniffer);
	lshell_start();
		
	return 0;		
}
