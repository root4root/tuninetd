#include "common.h"
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <errno.h>

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
    if (status == OFF) {
        message(INFO, "NFLOG: executing START command...");
        switch_guard(ON);
    }

    ts = curts;

    return 0;
}


void xnflog_start()
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
        message(ERROR, "NFLOG: no handle for group %i, can't bind, errno: %i. Abort.", globcfg.nf_group, errno);
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

    while ((rv = recv(fd, (void *)buf, BUFSIZE, 0))) {

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
