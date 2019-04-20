#ifndef _ARP_DECEIVE_H_
#define _ARP_DECEIVE_H_

#define MAC_LEN              6
#define IP_LEN               4
#define ETHER_ARP_PACKET_LEN 42
#define ETHER_HEADER_LEN     14

#define ARP_DEFAULT  0
#define ARP_REQUEST  1
#define ARP_RESPINSE 2

#pragma pack(push)
#pragma pack(1) 
struct arp_packet{
	/* 以太网头部 */
	unsigned char eth_dst[MAC_LEN];
	unsigned char eth_src[MAC_LEN];
	unsigned short eth_type;   
	/* arp请求/应答 */
	unsigned short ar_hrd;
	unsigned short ar_pro;
	unsigned char ar_hln;
	unsigned char ar_pln;
	unsigned short ar_op;
	unsigned char ar_sha[MAC_LEN];
	unsigned int ar_sip;
	unsigned char ar_dha[MAC_LEN];
	unsigned int ar_dip;
	unsigned char padding[18]; //填充
}arp_packet_s;
#pragma pack(pop)

void arp_deceive(char *deveice_name, char *trick_ip, char *target_ip, char flag);

#endif
