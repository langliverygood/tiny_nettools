#include <stdio.h>
#include <pthread.h>

#include "lshell.h"
#include "sniffer.h"

static pthread_t sniffer_td;

void *thread_sniffer()
{
	printf_sniffer();
	
	return NULL;
}

void func_sniffer(int argc, char **argv)
{
	int ret;
	
	ret = pthread_create(&sniffer_td, NULL, thread_sniffer, NULL);
	
	if(ret != 0)
	{
		printf("Sniffer thread failed to start!\n");
		return;
	}
	
	pthread_join(sniffer_td, NULL);
	
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
	ret = lshell_register(-1, "ls", "ls", test_ls);
	//lshell_register(ret, "cd", "cd", test_cd);
	lshell_register(-1, "sniffer", "sniffer", func_sniffer);
	lshell_start();
	
	printf("%d\n", ret);	
	return 0;		
}
