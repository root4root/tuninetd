#include <stdarg.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "common.h"
#include "net.h"

#define DEBUG_MODE 0


void do_debug(const char *msg, ...)
{
    if (DEBUG_MODE) {
        va_list argp;
        va_start(argp, msg);
        vfprintf(stderr, msg, argp);
        va_end(argp);
    }
}

void message(int mylogpriority, const char *msg, ...)
{
    int syslogpriority;

    if (mylogpriority == ERROR) {
        syslogpriority = LOG_ERR;
    } else if (mylogpriority == WARNING) {
        syslogpriority = LOG_WARNING;
    } else {
        syslogpriority = LOG_INFO;
    }

    va_list argp;
    va_start(argp, msg);

    if (globcfg.isdaemon == 0) {
        vfprintf(stderr, msg, argp);
        vfprintf(stderr, "\n", NULL);
    } else {
        openlog("tuninetd", 0, LOG_USER);
        vsyslog(syslogpriority, msg, argp);
        closelog();
    }

    va_end(argp);
}

static void to_syslog(const packet *pkt)
{
    uint8_t next_proto = 0;

    char src_ip[46] = {};
    char dst_ip[46] = {};

    uint32_t net_l_sig = (pkt->stack & NET_MASQ);
    uint8_t ip_ver = 0;

    if (net_l_sig == IPV4) {
        inet_ntop(AF_INET, ((ipv4_h*)pkt->network_l.header)->src, src_ip, 45);
        inet_ntop(AF_INET, ((ipv4_h*)pkt->network_l.header)->dst, dst_ip, 45);
        next_proto = ((ipv4_h*)pkt->network_l.header)->next_proto;
        ip_ver = IPv4_VER;
    }

    if (net_l_sig == IPV6) {
        inet_ntop(AF_INET6, ((ipv6_h*)pkt->network_l.header)->src, src_ip, 45);
        inet_ntop(AF_INET6, ((ipv6_h*)pkt->network_l.header)->dst, dst_ip, 45);
        next_proto = ((ipv6_h*)pkt->network_l.header)->next_proto;
        ip_ver = IPv6_VER;
    }

    if (ip_ver != 0) {
        message(INFO, "|- IPv%u %s > %s, NXT_HDR: 0x%02X (%s)", ip_ver, src_ip, dst_ip, next_proto, proto_name(next_proto));
    } else {
        message(INFO, "|- Not IPv4/6 protocol, L3 info not available");
    }

    if ((pkt->stack & LINK_MASQ) == 0) {
           return;
    }

    if ((pkt->stack & LINK_MASQ) == DOT1Q) {
        dot1q_h *vlan = (dot1q_h*)pkt->link_l.header;
        uint16_t vid = ntohs(vlan->pcv) & 0x0fff;

        message(
            INFO, "|- MAC: %02x:%02x:%02x:%02x:%02x:%02x > %02x:%02x:%02x:%02x:%02x:%02x, 802.1Q VID: %u, EtherType: 0x%04X (%s)",
            vlan->src_mac[0], vlan->src_mac[1], vlan->src_mac[2],
            vlan->src_mac[3], vlan->src_mac[4], vlan->src_mac[5],
            vlan->dst_mac[0], vlan->dst_mac[1], vlan->dst_mac[2],
            vlan->dst_mac[3], vlan->dst_mac[4], vlan->dst_mac[5],
            vid,
            ntohs(vlan->etype),
            ethertype_name(vlan->etype, NETWORK_ORDER)
        );

        return;
    }

    ether_h *eth = (ether_h*)pkt->link_l.header;

    message(
        INFO, "|- MAC: %02x:%02x:%02x:%02x:%02x:%02x > %02x:%02x:%02x:%02x:%02x:%02x, EtherType: 0x%04X (%s)",
        eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
        eth->src_mac[3], eth->src_mac[4], eth->src_mac[5],
        eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2],
        eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5],
        ntohs(eth->etype),
        ethertype_name(eth->etype, NETWORK_ORDER)
    );
}

static void to_pcap_file(const packet *pkt)
{
    static const pcap_file_h pfile_hdr = {0xA1B2C3D4, 0x2, 0x4, 0, 0, 0x40000, 0x1};

    ssize_t write_result;

    if (pkt->stack == 0) {
        message(ERROR, "Logger: can't write packet to pcap file, unknown headers");
        return;
    }

    int file = open(globcfg.pcap_file_path, O_RDWR | O_CREAT | O_APPEND, 0664);

    if (file < 0) {
        message(ERROR, "Logger: can't open or create pcap file");
        return;
    }

    struct stat st;

    if (fstat(file, &st) != 0) {
        message(ERROR, "Logger: can't get pcap file status");
        close(file);
        return;
    }

    if (st.st_size < sizeof(pcap_file_h)) {
        lseek(file, 0L, 0); //rewind to files beginning
        write_result = write(file, &pfile_hdr, sizeof(pcap_file_h));
    }

    packet pkt_copy = *pkt;
    ether_h eth = {{},{}, (uint16_t)htons(((pkt->stack & NET_MASQ) >> 8))};

    if ((pkt_copy.stack & LINK_MASQ) == 0) {
        pkt_copy.link_l.header = &eth;
        pkt_copy.link_l.h_len = ETH_HDR_LEN;
        pkt_copy.pkt_h.incl_len = pkt_copy.pkt_h.orig_len += ETH_HDR_LEN;
    }

    write_result = write(file, &pkt_copy.pkt_h, sizeof(pcap_pkt_h)); //packet pcap header
    write_result = write(file, pkt_copy.link_l.header, pkt_copy.link_l.h_len);

    if (pkt_copy.raw_pkt_ptr == pkt_copy.link_l.header) {
        write_result = write(file, pkt_copy.raw_pkt_ptr + pkt_copy.link_l.h_len, pkt_copy.pkt_h.incl_len - pkt_copy.link_l.h_len);
    } else {
        write_result = write(file, pkt_copy.raw_pkt_ptr, pkt_copy.pkt_h.incl_len - pkt_copy.link_l.h_len);
    }

    if (write_result < 0) {
        message(ERROR, "Logger: can't write to pcap file");
    }

    close(file);
}

void log_packet(const packet *pkt)
{
    to_syslog(pkt);

    if (globcfg.pcap_file_path != NULL) {
        to_pcap_file(pkt);
    }
}
