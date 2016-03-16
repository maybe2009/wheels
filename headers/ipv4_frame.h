#ifndef __DATAGRAMSTRUCTS_INCLUDED__
#define __DATAGRAMSTRUCTS_INCLUDED__
#include <stdlib.h>
#include <arpa/inet.h>

#pragma pack(1)
#define IP_VERSION(ip_frame)        ((ip_frame)->ip_vhl >> 4)
#define IP_HEADERLENGTH(ip_frame)   ((ip_frame)->ip_vhl & 0x0f)
#define TCP_HEADERLENGTH(tcp_frame) ((tcp_frame)->hdl >> 12)
#define IP_SET_MF(ip_frame)         ((ip_frame)->ip_offset = ((ip_frame)->ip_offset & 0x2000))
#define IP_SET_DF(ip_frame)         ((ip_frame)->ip_offset = ((ip_frame)->ip_offset & 0x4000))
#define IP_SET_RF(ip_frame)         ((ip_frame)->ip_offset = ((ip_frame)->ip_offset & 0x8000))
#define MASK_IP_MF                  0x2000 
#define MASK_IP_DF                  0x4000
#define MASK_IP_RF                  0x8000
#define MASK_TCP_FIN                0x01
#define MASK_TCP_SYN                0x02
#define MASK_TCP_RST                0x04
#define MASK_TCP_PSH                0x08
#define MASK_TCP_ACK                0x10
#define MASK_TCP_URG                0x20

/*Ethernet infomations*/
#define ETHERNET_HEADER_SIZE        14
#define ETHERNET_ADDR_LEN           6

/*Version code in link layer*/
#define VERSION_IS_IPv4             0X0800
#define VERSION_IS_ARP              0x0806

/*Version code in ipv4 header*/
#define VERSION_IS_TCP              0x06
#define VERSION_IS_UDP              0x11

struct frame_ethernet{
    u_char  dst[ETHERNET_ADDR_LEN];
    u_char  src[ETHERNET_ADDR_LEN];
    u_short type;
};

struct test{
};
/*28 bytes ARP frame*/
struct frame_arp{
    u_short arp_hd_ver;
    u_short arp_prtcl_ver;
    u_char  arp_hd_len;
    u_char  arp_prtcl_len;
    u_short arp_op;
    
    u_char  arp_src_addr[ETHERNET_ADDR_LEN];
    struct  in_addr arp_src_ip;
    
    u_char  arp_dst_addr[ETHERNET_ADDR_LEN];
    struct in_addr arp_dst_ip;
};

/*20 bytes IP header*/
struct frame_ip {
    u_char      ip_vhl;
    u_char      ip_tos;
    u_short     ip_len;
    u_short     ip_id;
    u_short     ip_offset;
    u_char      ip_ttl;
    u_char      ip_prtcl;
    u_short     ip_sum;

    struct in_addr  ip_src;
    struct in_addr  ip_dst;
};

struct frame_tcp{
    u_short      tcp_sport;
    u_short      tcp_dport;
    u_int        tcp_seq;
    u_int        tcp_ack;
    u_short      tcp_hdl;
    u_short      tcp_win;
    u_short      tcp_sum;
    u_short      tcp_ugp;
};

struct frame_udp{
    u_short      udp_sport;
    u_short      udp_dport;
    u_short      udp_len;
    u_short      udp_sum;
};

#endif
