#include <pcap.h>
#include <arpa/inet.h>

#include "common.h"
#include "net.h"
#include "xpcap.h"

static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    ts = header->ts.tv_sec;

    if (status == ON) {
        return;
    }

    message(INFO, "PCAP: executing START command...");

    switch_guard(ON);

    headers hdrs = {};
    uint8_t next_proto = 0;
    uint8_t ver = protocol_recognition(&hdrs, packet);

    char src_ip[46] = {};
    char dst_ip[46] = {};

    if (ver == IPv4_VER) {
        inet_ntop(AF_INET, hdrs.ipv4->src, src_ip, 45);
        inet_ntop(AF_INET, hdrs.ipv4->dst, dst_ip, 45);
        next_proto = hdrs.ipv4->next_proto;
    }

    if (ver == IPv6_VER) {
        inet_ntop(AF_INET6, hdrs.ipv6->src, src_ip, 45);
        inet_ntop(AF_INET6, hdrs.ipv6->dst, dst_ip, 45);
        next_proto = hdrs.ipv6->next_proto;
    }

    if (ver != 0) {
        message(INFO, "|- IPv%u %s > %s, NXT_HDR: 0x%02X (%s)", ver, src_ip, dst_ip, next_proto, proto_name(next_proto));
    } else {
        message(INFO, "|- Not IPv4/6 protocol, L3 info not available");
    }

    if (hdrs.ethernet == NULL) {
        return;
    }

    if (hdrs.ethernet->etype == 0x0081) { //VLAN 0x8100 NETWORK_ORDER

        uint16_t vid = ntohs(hdrs.ethernet->vlan_h[1]) & 0x0fff;

        message(
            INFO, "|- MAC: %02x:%02x:%02x:%02x:%02x:%02x > %02x:%02x:%02x:%02x:%02x:%02x, 802.1Q VID: %u, EtherType: 0x%04X (%s)",
            hdrs.ethernet->src_mac[0], hdrs.ethernet->src_mac[1], hdrs.ethernet->src_mac[2],
            hdrs.ethernet->src_mac[3], hdrs.ethernet->src_mac[4], hdrs.ethernet->src_mac[5],
            hdrs.ethernet->dst_mac[0], hdrs.ethernet->dst_mac[1], hdrs.ethernet->dst_mac[2],
            hdrs.ethernet->dst_mac[3], hdrs.ethernet->dst_mac[4], hdrs.ethernet->dst_mac[5],
            vid,
            ntohs(hdrs.ethernet->vlan_etype),
            ethertype_name(hdrs.ethernet->vlan_etype, NETWORK_ORDER)
        );

        return;
    }

    message(
        INFO, "|- MAC: %02x:%02x:%02x:%02x:%02x:%02x > %02x:%02x:%02x:%02x:%02x:%02x, EtherType: 0x%04X (%s)",
        hdrs.ethernet->src_mac[0], hdrs.ethernet->src_mac[1], hdrs.ethernet->src_mac[2],
        hdrs.ethernet->src_mac[3], hdrs.ethernet->src_mac[4], hdrs.ethernet->src_mac[5],
        hdrs.ethernet->dst_mac[0], hdrs.ethernet->dst_mac[1], hdrs.ethernet->dst_mac[2],
        hdrs.ethernet->dst_mac[3], hdrs.ethernet->dst_mac[4], hdrs.ethernet->dst_mac[5],
        ntohs(hdrs.ethernet->etype),
        ethertype_name(hdrs.ethernet->etype, NETWORK_ORDER)
    );

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
