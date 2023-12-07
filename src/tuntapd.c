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

    packet pkt = {};
    pkt.raw_pkt_ptr = (void*)buf;
    stack_recognition(&pkt);

    struct timeval ts;
    gettimeofday(&ts, NULL);

    pkt.pkt_h.incl_len = nread;
    pkt.pkt_h.orig_len = nread;
    pkt.pkt_h.ts_sec = ts.tv_sec;
    pkt.pkt_h.ts_usec = ts.tv_usec;

    log_packet(&pkt);
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
    static const char *optString = "i:m:w:dhv";

    globcfg.isdaemon = 0;
    globcfg.pid = 0;
    globcfg.pcap_file_path = NULL;
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
            case 'w':
                globcfg.pcap_file_path = optarg;
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

        if (chdir("/") < 0) {
            message(WARNING, "can't change directory");
        }

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
