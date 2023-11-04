#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <errno.h>
#include <arpa/inet.h>

#include "common.h"
#include "net.h"
#include "xnflog.h"

#define BUFSIZE 65536
#define NFNLBUFSIZ 150000

static char *buf;
static struct nflog_handle *h;
static struct nflog_g_handle *qh;
static int fd;

static void setnlbufsiz(unsigned int size, struct nflog_handle *h)
{
    //This function returns new buffer size
    message(INFO, "NFLOG: adjust nfnl_rcvbufsiz to %u", nfnl_rcvbufsiz(nflog_nfnlh(h), size));
}

static int callback(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *ldata, void *data)
{
    ts = curts;

    if (status == ON) {
        return 0;
    }

    char *payload;

    int payload_fetch_result = nflog_get_payload(ldata, &payload);

    if (payload_fetch_result < 0) {
        return 0;
    }

    message(INFO, "NFLOG: executing START command...");

    switch_guard(ON);

    headers hdrs = {};
    uint8_t next_proto = 0;
    uint8_t ver = protocol_recognition(&hdrs, (uint8_t*)payload);

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

    struct nfulnl_msg_packet_hw *hw = nflog_get_packet_hw(ldata);

    if (hw) {
        message(
            INFO, "|- MAC: %02x:%02x:%02x:%02x:%02x:%02x, DevIndex: %u",
            hw->hw_addr[0], hw->hw_addr[1], hw->hw_addr[2],
            hw->hw_addr[3], hw->hw_addr[4], hw->hw_addr[5],
            nflog_get_indev(ldata)
        );
    }

    return 0;
}


static void xnflog_start()
{
    buf = calloc(BUFSIZE, sizeof(char));

    h = nflog_open();

    short int pf_available = 3; //AF_INET, AF_INET6, AF_BRIDGE

    if (!h) {
        message(ERROR, "NFLOG: error during nflog_open(). Abort.");
        exit(1);
    }

    setnlbufsiz(NFNLBUFSIZ, h);

    pf_available -= nflog_bind_pf(h, AF_INET) < 0 ? 1 : 0;
    pf_available -= nflog_bind_pf(h, AF_INET6) < 0 ? 1 : 0;
    pf_available -= nflog_bind_pf(h, AF_BRIDGE) < 0 ? 1 : 0;
   
    if (pf_available == 0) {
        message(ERROR, "NFLOG: can't bind to any protocol family (IPv4, IPv6 or BRIDGE)");
        exit(1);
    }

    qh = nflog_bind_group(h, globcfg.nf_group);

    if (!qh) {
        message(ERROR, "NFLOG: no handle for group %li, can't bind, errno: %i. Abort.", globcfg.nf_group, errno);
        exit(1);
    }

    if (nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff) < 0) {
        message(ERROR, "NFLOG: can't set NFULNL_COPY_PACKET mode. Abort.");
        exit(1);
    }

    nflog_callback_register(qh, &callback, NULL);

    fd = nflog_fd(h);
}

void xnflog_stop()
{
    message(INFO, "NFLOG: Shutting down...");
    shutdown(fd, SHUT_RD);
    //close(fd);
    nflog_unbind_group(qh);
    nflog_unbind_pf(h, AF_INET);
    nflog_unbind_pf(h, AF_INET6);
    nflog_unbind_pf(h, AF_BRIDGE);
    nflog_close(h);
    free(buf);
}


void *nflog_x(void *x_void_ptr)
{
    xnflog_start();

    ssize_t rv;

    while ((rv = recv(fd, (void *)buf, BUFSIZE - 1, 0))) {
        if (rv >= 0) {
            nflog_handle_packet(h, buf, rv);
        } else if (errno == ENOBUFS) {
            message(WARNING, "NFLOG: warning! No enough nfnlbufsiz...");
        } else {
            break;
        }
    }

    message(WARNING, "NFLOG: shut down with code %i. Check errno.h for details.", errno);

    xnflog_stop();

    return 0;
}
