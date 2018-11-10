static int callback(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *ldata, void *data)
{
    if (status == OFF) {
        my_info("NFLOG module: executing START command...");
        switch_guard(ON);
    }
    
    ts = curts;
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
        my_err("error during nflog_open()");
        exit(1);
    }
    
    if (nflog_unbind_pf(h, AF_INET) < 0) {
        my_err("error nflog_unbind_pf()");
        exit(1);
    }
    
    if (nflog_bind_pf(h, AF_INET) < 0) {
        my_err("error during nflog_bind_pf()");
        exit(1);
    }
    qh = nflog_bind_group(h, globcfg.nf_group);
    if (!qh) {
        my_err("no handle for group %i", globcfg.nf_group);
        exit(1);
    }

    if (nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff) < 0) {
        my_err("can't set packet copy mode");
        exit(1);
    }

    nflog_callback_register(qh, &callback, NULL);

    fd = nflog_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nflog_handle_packet(h, buf, rv);
    }
    
    return 0;
}
