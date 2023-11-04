#include "tuntapd.h"

#define BUFSIZE 2000

struct globcfg_t globcfg;
static char progname[] = "tuntapd";

static void cread(int fd, char *buf, int n)
{
    int nread;

    if ((nread = read(fd, buf, n)) < 0) {
        message(ERROR, "%s: error, while reading data. Abort.", progname);
        exit(1);
    }

    if (globcfg.isdaemon == 1) {
        return;
    }

    headers hdrs = {};
    uint8_t next_proto = 0;
    uint8_t ver = protocol_recognition(&hdrs, (uint8_t*)buf);

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

int main(int argc, char *argv[])
{
    int tap_fd;
    char buffer[BUFSIZE];

    build_config(argc, argv);
    check_config_and_daemonize();

    signal(SIGTERM, sigterm_handler);
    signal(SIGHUP, sighup_handler);
    signal(SIGUSR1, sigusr_handler);
    signal(SIGINT, sigterm_handler);


    if ((tap_fd = tun_alloc(globcfg.dev_name, globcfg.dev_mode | IFF_NO_PI)) < 0) {
        message(ERROR, "%s: mapping to tun/tap interface %s mode 0x%04x failed. Abort.", progname, globcfg.dev_name, globcfg.dev_mode);
        exit(1);
    }

    while (1) {
        cread(tap_fd, buffer, BUFSIZE);
    }

    close(tap_fd);

    return 0;
}

static int tun_alloc(char *dev, int flags)
{
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    if ( (fd = open(clonedev, O_RDWR)) < 0 ) {
        message(ERROR, "%s: unable to open clonable device %s", progname, clonedev);
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

static void build_config(int argc, char **argv)
{
    int opt = 0;
    static const char *optString = "i:m:dhv";

    globcfg.isdaemon = 0;
    globcfg.pid = 0;
    globcfg.dev_mode = IFF_TUN;

    opt = getopt(argc, argv, optString);

    while (opt != -1) {
        switch( opt ) {
            case 'v':
                version();
                exit(0);
            case 'i':
                globcfg.dev_name = optarg;
                break;
            case 'd':
                globcfg.isdaemon = 1;
                break;
            case 'm':
                if (strcmp("tap", optarg) == 0) {
                   globcfg.dev_mode = IFF_TAP;
                } else if (strcmp("tun", optarg) == 0) {
                   globcfg.dev_mode = IFF_TUN;
                } else {
                    globcfg.dev_mode = 0;
                }
                break;
            case 'h':   //go to the next case, same action
            case '?':
                usage();
                break;
            default:
                exit(1);
                break;
        }

        opt = getopt(argc, argv, optString);
    }
}

static void check_config_and_daemonize()
{
    if (globcfg.dev_name == NULL) {
        message(ERROR, "%s: tun/tap device must be specified. Abort.", progname);
        usage();
        exit(1);
    }

    if (globcfg.dev_mode != IFF_TUN && globcfg.dev_mode != IFF_TAP) {
        message(ERROR, "%s: device mode must be \"tun\" or \"tap\". Abort.", progname);
        exit(1);
    }

    if (globcfg.isdaemon == 1) {
        globcfg.pid = fork();

        if (globcfg.pid < 0) {
            message(ERROR, "%s: can't fork process. Abort.", progname);
            exit(1);
        }

        if (globcfg.pid > 0) {
            message(INFO, "---");
            message(INFO, "%s: success! Has been started with PID: %i", progname, globcfg.pid);
            exit(0);
        }

        chdir("/");

        setsid();

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    } else {
        message(INFO, "%s: started with pid %d", progname, getpid());
    }
}

static void sighup_handler(int signo)
{
    message(WARNING, "%s: SIGHUP caught. NoOp.", progname);
}

static void sigusr_handler(int signo)
{
    message(INFO, "%s: SIGUSR1 caught. Running on %s, mode 0x%04x", progname, globcfg.dev_name, globcfg.dev_mode);
}

static void sigterm_handler(int signo)
{
    message(INFO, "%s: SIGTERM caught. Shutting down...", progname);
    exit(0);
}

static void usage(void) {
    fprintf(stderr, VERSION);
    fprintf(stderr, "\nStub for tun/tap device to keep it alive.\n");
    fprintf(stderr, "\nUsage: %s -i <ifname> [-m <iftype>] [-d]\n\n", progname);
    fprintf(stderr, "-i <ifname>: interface to use with.\n");
    fprintf(stderr, "-m <iftype>: 'tun' or 'tap'. Default is 'tun'. \n");
    fprintf(stderr, "-d: daemonize process. Check for errors before use.\n\n");
    fprintf(stderr, "-h: print this help\n");
    fprintf(stderr, "-v: print version\n\n");
    exit(1);
}

static void version() {
    fprintf(stderr, VERSION);
}
