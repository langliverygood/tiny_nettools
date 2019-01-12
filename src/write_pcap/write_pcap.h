#ifndef _WRITE_PCAP_H_
#define _WRITE_PCAP_H_

#define PACKET_MAX_NUM 100

#pragma pack(push)
#pragma pack(1)
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

struct packete_header 
{
	uint32_t timestamp_high;
	uint32_t timestamp_low;
	uint32_t caplen;
	uint32_t len;
};
#pragma pack(pop)

char create_pcap_file(char *file_name, struct pcap_file_header pcap_h);

#endif
