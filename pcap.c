//Author: root4root@gmail.com

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    ts = header->ts.tv_sec;
}


void *inc_x(void *x_void_ptr)
{
    struct bpf_program filter;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
   
    handle = pcap_open_live(globcfg.dev_name, BUFSIZ, 0, 10, errbuf);
  
    if (handle == NULL) {
        my_err("Pcap: unable to open interface. %s", errbuf);
        exit(1);
    }
  
    if (globcfg.pcap_filter != NULL) {
        if (pcap_compile(handle, &filter, globcfg.pcap_filter, 0, PCAP_NETMASK_UNKNOWN) != 0) {
            my_err("Wrong libpcap filter: \"%s\"", globcfg.pcap_filter);
            exit(1);
        }
 
        pcap_setfilter(handle, &filter);
    }
  
    pcap_loop(handle, -1, got_packet, NULL);
    
    pcap_close(handle);
}
