#include "common.h"
#include <pcap.h>

static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    ts = header->ts.tv_sec;
    //do_debug("Packet timestamp %lu ...\n", ts);
}

void *pcap_x(void *x_void_ptr)
{
    struct bpf_program filter;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    short int loop_status = 0;

    handle = pcap_open_live(globcfg.dev_name, BUFSIZ, 0, 10, errbuf);

    if (handle == NULL) {
        message(ERROR, "Pcap: unable to open interface %s. Abort.", errbuf);
        exit(1);
    }

    if (globcfg.pcap_filter != NULL) {
        if (pcap_compile(handle, &filter, globcfg.pcap_filter, 0, PCAP_NETMASK_UNKNOWN) != 0) {
            message(ERROR, "Pcap: wrong filter: \"%s\". %s. Abort.", globcfg.pcap_filter, pcap_geterr(handle));
            exit(1);
        }

        pcap_setfilter(handle, &filter);
    }

    loop_status = pcap_loop(handle, -1, got_packet, NULL);

    if (loop_status == -1) {
        message(ERROR, "Pacap: %s. Abort.", pcap_geterr(handle));
        exit(1);
    }

    pcap_close(handle);

    return 0;
}
