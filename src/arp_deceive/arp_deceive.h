#ifndef _ARP_DECEIVE_H_
#define _ARP_DECEIVE_H_

#pragma pack(push)
#pragma pack(1) 
struct arp_packet{
	/* 以太网头部 */
	unsigned char eth_dst[6];
	unsigned char eth_src[6];
	unsigned short eth_type;   
	/* arp请求/应答 */
	unsigned short ar_hrd;
	unsigned short ar_pro;
	unsigned char ar_hln;
	unsigned char ar_pln;
	unsigned short ar_op;
	unsigned char ar_sha[6];
	unsigned char ar_sip[4];
	unsigned char ar_dha[6];
	unsigned char ar_dip[4];
	unsigned char padding[18]; //填充
}arp_packet_s;
#pragma pack(pop)

void arp_deceive(char *deveice_name, char *trick_ip, char *target_ip);

#endif
