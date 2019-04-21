#ifndef _ARP_H_
#define _ARP_H_

#define MAC_LEN              6  /* mac地址长度*/
#define IP_LEN               4  /* ip地址长度*/
#define ETHER_ARP_PACKET_LEN 42 /* arp包长度*/
#define ETHER_HEADER_LEN     14 /* 以太网头部长度*/

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
	unsigned char padding[18]; /* 填充 */
}arp_packet_s;
#pragma pack(pop)

void arp_deceive(char *deveice_name, char *trick_ip, char *target_ip, char flag);
void set_time(unsigned int interval_ms);

#endif
