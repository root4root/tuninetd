#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/time.h>

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
    if (globcfg.ack_only == OFF && status == ON) {
        ts = curts;
        return 0;
    }

    char *payload;

    int payload_length = nflog_get_payload(ldata, &payload);

    if (payload_length < 0) {
        return 0;
    }

    packet pkt = {};
    pkt.raw_pkt_ptr = (void*)payload;
    stack_recognition(&pkt);

    if (globcfg.ack_only == ON && status == ON) {
        if ((pkt.stack & TRANSP_MASQ) == TCP && (((tcp_h*)pkt.transport_l.header)->flags & ACK) > 0) {
            ts = curts;
        }
        return 0;
    }

    if (switch_guard(ON) == FAIL) {
        return 0; //Most probably another concurrent thread has switched state just before
    }

    message(INFO, "NFLOG: Start command done");

    if ((pkt.stack & LINK_MASQ) == 0) {
        uint16_t link_layer_h_len = nflog_get_msg_packet_hwhdrlen(ldata);
        pkt.link_l.h_len = link_layer_h_len;

        if (link_layer_h_len == ETH_HDR_LEN) {
            pkt.stack |= ETH;
            payload_length += ETH_HDR_LEN;
        }

        if (link_layer_h_len == DOT1Q_HDR_LEN) {
            pkt.stack |= DOT1Q;
            payload_length += DOT1Q;
        }

        pkt.link_l.header = nflog_get_msg_packet_hwhdr(ldata);
    }


    struct timeval ts;

    if (nflog_get_timestamp(ldata, &ts) < 0) {
        gettimeofday(&ts, NULL);
    }

    pkt.pkt_h.incl_len = payload_length;
    pkt.pkt_h.orig_len = payload_length;
    pkt.pkt_h.ts_sec = ts.tv_sec;
    pkt.pkt_h.ts_usec = ts.tv_usec;

    log_packet(&pkt);

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
