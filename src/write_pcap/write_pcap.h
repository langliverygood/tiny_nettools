#ifndef _WRITE_PCAP_H_
#define _WRITE_PCAP_H_

#define PACKET_MAX_NUM 100

#pragma pack(push)
#pragma pack(1)
/* pcap文件头部 */
struct pcap_file_header 
{
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t linktype;
};

/* packet头部 */
struct packete_header 
{
	uint32_t timestamp_high;
	uint32_t timestamp_low;
	uint32_t caplen;
	uint32_t len;
};
#pragma pack(pop)

/***************************************************************/
/**函  数：create_pcap_file *************************************/
/* 说  明：在创建pcap文件并初始化 **********************************/
/* 参  数：file_name pcap文件名（包含路径） ************************/
/* 参  数：pcap_h pcap文件头 *************************************/
/* 返回值：0 创建成功**********************************************/
/*        1 创建失败*********************************************/
/***************************************************************/
char create_pcap_file(char *file_name, struct pcap_file_header pcap_h);

#endif
