#include "common.h"

static int tun_alloc(char *dev, int flags) 
{
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    if ( (fd = open(clonedev, O_RDWR)) < 0 ) {
        message(ERROR, "Tun: unable to open clonable device %s", clonedev);
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
        close(fd);
        return err;
    }

    return fd;
}

static int cread(int fd, char *buf, int n)
{
    int nread;

    if ((nread = read(fd, buf, n)) < 0) {
        message(ERROR, "Tun: error, while reading data. Abort.");
        exit(1);
    }

    return nread;
}

void *tun_x(void *x_void_ptr)
{
    int tap_fd;
    int nread;
    char buffer[BUFSIZE];

    struct timespec tim;

    tim.tv_sec = 0;
    tim.tv_nsec = 20000000;

    if ( (tap_fd = tun_alloc(globcfg.dev_name, globcfg.dev_mode | IFF_NO_PI)) < 0 ) {
        message(ERROR, "Tun: connection to tun/tap interface %s failed. Abort.", globcfg.dev_name);
        exit(1);
    }

    while (1) {
        nread = cread(tap_fd, buffer, BUFSIZE);

        if (globcfg.pcap_filter != NULL) {
            nanosleep(&tim, NULL);
            if ( (long)(curts - ts) < 2 ) {
                do_debug("Read %d bytes from the tap interface\n", nread);
                break;
            } else {
                do_debug("Delta is not small enough...\n");
            }
        } else {
             break;
        }
    }

    close(tap_fd);

    message(INFO, "TUN/TAP module: executing START command...");

    switch_guard(ON);

    return 0;
}
