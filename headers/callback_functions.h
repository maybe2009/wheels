#ifndef __CALLBACK_FUNCTIONS__INCLUDED__
#define __CALLBACK_FUNCTIONS__INCLUDED__
#include <stdio.h>
#include <pcap.h>
#include "ipv4_frame.h"
#include "ipv4_handles.h"

void    got_packet(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet);

#endif
