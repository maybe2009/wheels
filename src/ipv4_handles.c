#include "../headers/ipv4_handles.h"

void display_raw(const u_char *packet, int packet_size)
{
    int i;
    const u_char *ptr;
    
    printf("packet length is %d bytes\n", packet_size);

    for (i = 0, ptr = packet; i < packet_size; ++i) {
        printf("%2x ", *ptr++);    
    }
    printf("\n");

    return;
}

void 
ip_handle(const struct frame_ip *ip_frame)
{
    u_char ip_type = ip_frame->ip_prtcl;

    printf("IP:\n");
    printf("IP Type : %u\n", ip_type);
    printf("IP Version : %u\n", IP_VERSION(ip_frame));
    printf("IP Length : %u\n", ntohs(ip_frame->ip_len));
    printf("Source IP : %s\n", inet_ntoa(ip_frame->ip_src)); 
    printf("Destination IP : %s\n", inet_ntoa(ip_frame->ip_dst)); 
     
    printf("SRC HOST IS %s\n", gethostbyip(&(ip_frame->ip_src), 4, AF_INET));
    printf("DST HOST IS %s\n", gethostbyip(&(ip_frame->ip_dst), 4, AF_INET));

    switch (ip_type)
    {
        
        case VERSION_IS_TCP : {
            tcp_handle((struct frame_tcp *)
                    ((char*)ip_frame + IP_HEADERLENGTH(ip_frame)));
            break;
        } 
        
        case VERSION_IS_UDP : {
            udp_handle((struct frame_udp *)
                    ((char*)ip_frame + IP_HEADERLENGTH(ip_frame)));
            break;
        }
        
        default : {
            printf("Unknow Version Code In IP header.");
            break;    
        }
    }
    return;
}

void 
tcp_handle(const struct frame_tcp *tcp_frame)
{
    printf("TCP:\n");
    printf("\tSource Port : %u\n", ntohs(tcp_frame->tcp_sport));
    printf("\tSource Port : %u\n", ntohs(tcp_frame->tcp_dport));
    printf("\tSequence Number : %u\n", ntohl(tcp_frame->tcp_seq));
    printf("\tAcknowledge Number : %u\n", ntohl(tcp_frame->tcp_ack));
    printf("\tHeader Length : %u\n", ntohs(tcp_frame->tcp_hdl)); 
    printf("\tWIN Size : %u\n", ntohs(tcp_frame->tcp_win)); 
    printf("\tUrgency : %u\n", ntohs(tcp_frame->tcp_ugp));

    return;
}

void
udp_handle(const struct frame_udp *udp_frame)
{
    printf("UDP:\n");
    printf("\tSource Port : %u\n", ntohs(udp_frame->udp_sport));
    printf("\tDestination Port : %u\n", ntohs(udp_frame->udp_dport));
    printf("\tUDP Length : %u\n", ntohs(udp_frame->udp_len));
    
    return;
}

void
arp_handle(const struct frame_arp *arp_frame)
{
    printf("ARP: \n");
    printf("SRC HOST IS %s\n", gethostbyip(&(arp_frame->arp_src_addr), 4, AF_INET));
    printf("DST HOST IS %s\n", gethostbyip(&(arp_frame->arp_dst_addr), 4, AF_INET));
    
    switch (ntohs(arp_frame->arp_op))
    {
case 1: {
            /*ARP request*/
            printf("ARP Request:\n");
            
            printf("\tWho has %s tell %x:%x:%x:%x:%x:%x\n",
                    inet_ntoa(arp_frame->arp_dst_ip),
                    arp_frame->arp_src_addr[0],
                    arp_frame->arp_src_addr[1],
                    arp_frame->arp_src_addr[2],
                    arp_frame->arp_src_addr[3],
                    arp_frame->arp_src_addr[4],
                    arp_frame->arp_src_addr[5]
                    /*Use ONLY ONE inet_ntoa call in ONE 
                     *printf statement! There is a bug in
                     *inet_ntoa... :-( 
                     *I'm crying....
                     */
                  );
                break;
        }

case 2: {
            /*ARP response*/
            printf("ARP Response:\n");
            printf("\tI am %s. My MAC is : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
                    inet_ntoa(arp_frame->arp_src_ip),
                    arp_frame->arp_src_addr[0],
                    arp_frame->arp_src_addr[1],
                    arp_frame->arp_src_addr[2],
                    arp_frame->arp_src_addr[3],
                    arp_frame->arp_src_addr[4],
                    arp_frame->arp_src_addr[5]);
            break;
        }

case 3: {
            /*RARP request*/
            printf("Unsupport RARP now...\n");
            break;
        }

case 4: {
            /*RARP response*/
            printf("Unsupport RARP now...\n");
            break;
        }
    
    }
    return;
}

char *
gethostbyip(const void *addr, int size, int family)
{
    struct hostent *hostent_t;

    if ((hostent_t = gethostbyaddr(addr, size, family)) == NULL) {
        perror("[ERROR]gethostbyaddr:");
        return NULL;
    } else {
        return hostent_t->h_name;
    }
}

