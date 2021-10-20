#include "common.h"
#include <libnetfilter_log/libnetfilter_log.h>
#include <errno.h>

static int callback(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *ldata, void *data)
{
    if (status == OFF) {
        message(INFO, "NFLOG module: executing START command...");
        switch_guard(ON);
    }

    ts = curts;

    return 0;
}

void *nflog_x(void *x_void_ptr)
{
    struct nflog_handle *h;
    struct nflog_g_handle *qh;
    ssize_t rv;
    char buf[4096];
    int fd;

    h = nflog_open();

    if (!h) {
        message(ERROR, "Error during nflog_open(). Abort.");
        exit(1);
    }

    if (nflog_unbind_pf(h, AF_INET) < 0) {
        message(ERROR, "Error nflog_unbind_pf(). Abort.");
        exit(1);
    }

    if (nflog_bind_pf(h, AF_INET) < 0) {
        message(ERROR, "Error during nflog_bind_pf(). Abort");
        exit(1);
    }

    qh = nflog_bind_group(h, globcfg.nf_group);

    if (!qh) {
        message(ERROR, "No handle for group %i, can't bind. Abort.", globcfg.nf_group);
        exit(1);
    }

    if (nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff) < 0) {
        message(ERROR, "Can't set NFULNL_COPY_PACKET mode. Abort.");
        exit(1);
    }

    nflog_callback_register(qh, &callback, NULL);

    fd = nflog_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nflog_handle_packet(h, buf, rv);
    }

    message(WARNING, "NFLOG module shut down with code %i. Check errno.h for details.", errno);

    nflog_close(h);

    return 0;
}
