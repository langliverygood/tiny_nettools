#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "write_pcap.h"

char create_pcap_file(char *file_name, struct pcap_file_header pcap_h)
{
	FILE *fp;
	char cmd[256];
	int i;
	
	memset(cmd, 0, sizeof(cmd));
	
	sprintf(cmd, "%s", "mkdir -p ");
	i = strlen(file_name) - 1;
	while(file_name[i] != '/')
	{
		i--;
	}
	strncat(cmd, file_name, i + 1);
	system(cmd);
	
	fp = fopen(file_name, "w+");
	if(fp == NULL)
	{
		return 1;
	}
	
	fwrite((const void *)&pcap_h, 1, sizeof(pcap_h), fp);
	fclose(fp);
	
	return 0;
}
