#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "../headers/AFu_callback.h"

int main(int argc, char *argv[])
{
    int           link_layer_type, snaplen_i, promisc_i, timeout_i; 
    int           active_state, rfmon_i;
    char         *dev = argv[1];
    char          err_buf[PCAP_ERRBUF_SIZE];    
    pcap_t       *handle;
    const char   *filter_expression;
    bpf_u_int32   net_id, net_mask;
    
    struct in_addr      netid_addr_t, netmask_addr_t;
    struct bpf_program  bpf_t;

    filter_expression = argv[1];
    snaplen_i          = 2048;
    promisc_i          = 1;
    timeout_i          = 1;
    rfmon_i            = 0;

    if (argv[1] != NULL) {
        dev = argv[1];
    
    } else {
        dev = pcap_lookupdev(err_buf);
        if (dev == NULL) {
            fprintf(stderr, "Find Devicd Error: %s\n", err_buf);
            return -1;
        }
    }
    printf("Device %s\n", dev);
    
    if (argv[2] == NULL) {
        filter_expression = NULL;

    } else {
        filter_expression = argv[2];
    }

    printf("filter : %s\n", filter_expression);

    if (pcap_lookupnet(dev, &net_id, &net_mask, err_buf)) {
        fprintf(stderr, "Couldn't get net mask from device %s: %s\n", 
                dev, err_buf);
        net_id   = 0;
        net_mask = 0;
        
        netid_addr_t.s_addr = net_id;
        netmask_addr_t.s_addr = net_mask;

        return -1;
    }

    printf("Net ID = %s\nNet mask = %s\n", inet_ntoa(netid_addr_t), 
           inet_ntoa(netmask_addr_t));
    
//    handle = pcap_open_live(dev, 2048, 1, 1, err_buf);
    handle = pcap_create(dev, err_buf);
        
    if (handle == NULL) {
        fprintf(stderr, "[ERROR]Open device %s fails: %s\n", dev, err_buf);
        return -1;
    }
    
 
    if (pcap_can_set_rfmon(handle) == 1) {
        printf("[Message]Monitor mode support detected\n");
        if (pcap_set_rfmon(handle, rfmon_i) == 0) {
            printf("[OK]Set rfmon  to %d success!\n", rfmon_i);
        
        } else {
            fprintf(stderr, "[ERROR]Set rfmon fail: %s\n", pcap_geterr(handle));
        }

    } else {
        fprintf(stderr, "[Message]Moniitor mode unsupported: %s\n", 
                pcap_geterr(handle));
    } 
    
    if (pcap_set_snaplen(handle, snaplen_i) != 0) {
        fprintf(stderr, "[ERROR]Couldn't set snap length ; %s\n", 
                pcap_geterr(handle));
    
    } else {
        fprintf(stdout, "[OK]Set snap length to %d\n", snaplen_i);
    }

    if (pcap_set_promisc(handle, promisc_i) != 0) {
        fprintf(stderr, "[ERROR]Couldn't set promisc ; %s\n", 
                pcap_geterr(handle));
    
    } else {
        fprintf(stdout, "[OK]Set promisc to %d\n", promisc_i);
    }
    
    if (pcap_set_timeout(handle, timeout_i) != 0) {
        fprintf(stderr, "[ERROR]Couldn't set time out ; %s\n", 
                pcap_geterr(handle));
    
    } else {
        fprintf(stdout, "[OK]Set time out to %d\n", timeout_i);
    }
    
    if ((active_state = pcap_activate(handle)) != 0) {
        fprintf(stderr, "[Active Report]: return %d on %s\n", active_state,
                pcap_geterr(handle));
        return -1;

    } else {
        fprintf(stdout, "[Active Report]: Success\n");
    }

    if ((link_layer_type = pcap_datalink(handle)) != 1) {
        fprintf(stderr, "[Error]get datalink: %s\n", pcap_geterr(handle));
        return -1;
    
    } else {
        fprintf(stdout, "[Message]Link layer type: %d\n", link_layer_type);
    }
    
    if (pcap_compile(handle, &bpf_t, filter_expression,
        0, net_mask) == -1)
    {
        fprintf(stderr, "[ERROR]Couldn't parse filter %s: %s\n", 
                filter_expression, pcap_geterr(handle));
    
    } else {
        fprintf(stdout, "[OK]Set compile ok, filter:%s\n", filter_expression);
    }

    if (pcap_setfilter(handle, &bpf_t) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_expression, pcap_geterr(handle));
        return -1;
    
    } else {
        fprintf(stdout, "[OK]Set filter success\n");
    }
  
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);

    return 0;
}
