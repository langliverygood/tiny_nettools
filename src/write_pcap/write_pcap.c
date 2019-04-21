#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "write_pcap.h"

/***************************************************************/
/* 函  数：create_pcap_file *************************************/
/* 说  明：在创建pcap文件并初始化 **********************************/
/* 参  数：file_name pcap文件名(包含路径) *************************/
/* 参  数：pcap_h pcap文件头 *************************************/
/* 返回值：0 创建成功**********************************************/
/*        1 创建失败*********************************************/
/***************************************************************/
char create_pcap_file(char *file_name, struct pcap_file_header pcap_h)
{
	int i;
	char cmd[256];
	FILE *fp;
	
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
