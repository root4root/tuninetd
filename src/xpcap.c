#include <pcap.h>
#include <arpa/inet.h>

#include "common.h"
#include "net.h"
#include "xpcap.h"

static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *pcap_pkt)
{

    if (globcfg.ack_only == OFF && status == ON) {
        ts = header->ts.tv_sec;
        return;
    }

    packet pkt = {};
    pkt.raw_pkt_ptr = (void*)pcap_pkt;
    stack_recognition(&pkt);

    if (globcfg.ack_only == ON && status == ON) {
        if ((pkt.stack & TRANSP_MASQ) == TCP && (((tcp_h*)pkt.transport_l.header)->flags & ACK) > 0) {
            ts = header->ts.tv_sec;
        }
        return;
    }

    if (switch_guard(ON) == FAIL) {
        return; //Most probably another concurrent thread has switched state just before
    }

    message(INFO, "PCAP: executing START command...");

    pkt.pkt_h.incl_len = header->caplen;
    pkt.pkt_h.orig_len = header->len;
    pkt.pkt_h.ts_sec = header->ts.tv_sec;
    pkt.pkt_h.ts_usec = header->ts.tv_usec;

    log_packet(&pkt);

}

void *pcap_x(void *x_void_ptr)
{
    struct bpf_program filter;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    short int loop_status = 0;

    handle = pcap_open_live(globcfg.dev_name, BUFSIZ, 0, 10, errbuf); //!!!!

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
