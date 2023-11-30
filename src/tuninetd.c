#include "tuninetd.h"

//glob vars--
short int debug;
short int status;
atomic_ulong ts; // @suppress("Type cannot be resolved")
unsigned long curts;
struct globcfg_t globcfg = {};
//--glob vars

static char progname[] = "tuninetd";

int main(int argc, char *argv[])
{
    curts = time(NULL);

    build_config(argc, argv);
    check_config_and_daemonize();
    thread_init(); //Initialize our workers (thread.c)

    struct timespec tim;

    tim.tv_sec = 1;
    tim.tv_nsec = 0;

    signal(SIGTERM, sigterm_handler);
    signal(SIGHUP, sighup_handler);
    signal(SIGUSR1, sigusr_handler);
    signal(SIGINT, sigterm_handler);

    while (1) {

        nanosleep(&tim, NULL); //Tick

        curts = time(NULL);

        if (ts != 0 && status == ON && ((long)(curts - ts) >= globcfg.ttl)) {
            message(INFO, "CORE: executing STOP command...");
            switch_guard(OFF);
        }
    }

    free(globcfg.cmd_path_start);
    free(globcfg.cmd_path_stop);

    return 0;
}


void build_config(int argc, char **argv)
{
    int opt = 0;
    static const char *optString = "i:t:c:f:m:n:w:adhv";

    globcfg.ack_only = 0;
    globcfg.isdaemon = 0;
    globcfg.pid = 0;
    globcfg.cmd_path = NULL;
    globcfg.pcap_file_path = NULL;
    globcfg.ttl = 600;
    globcfg.nf_group = -1;

    opt = getopt( argc, argv, optString);

    while( opt != -1 ) {
        switch( opt ) {
            case 'a':
                globcfg.ack_only = 1;
                break;
            case 'v':
                version();
                exit(0);
            case 'i':
                globcfg.dev_name = optarg;
                break;
            case 't':
                globcfg.ttl = atoi(optarg);
                break;
            case 'c':
                globcfg.cmd_path = optarg;

                globcfg.cmd_path_start = malloc(strlen(optarg) + 23);
                strcpy(globcfg.cmd_path_start, optarg);
                strcat(globcfg.cmd_path_start, " start > /dev/null 2>&1");

                globcfg.cmd_path_stop = malloc(strlen(optarg) + 22);
                strcpy(globcfg.cmd_path_stop, optarg);
                strcat(globcfg.cmd_path_stop, " stop > /dev/null 2>&1");
                break;
            case 'w':
                globcfg.pcap_file_path = optarg;
                break;
            case 'f':
                globcfg.pcap_filter = optarg;
                break;
            case 'n':
                globcfg.nf_group = atoi(optarg);
                break;
            case 'd':
                globcfg.isdaemon = 1;
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

void check_config_and_daemonize()
{
    if (globcfg.dev_name == NULL && globcfg.nf_group < 0) {
        message(ERROR, "Network device or nflog-group must be specified. Abort.");
        usage();
        exit(1);
    }

    if (globcfg.cmd_path == NULL) {
        message(ERROR, "Executable path must be specified. Abort.");
        usage();
        exit(1);
    }

    if (globcfg.isdaemon == 1) {
        globcfg.pid = fork();

        if (globcfg.pid < 0) {
            message(ERROR, "Can't fork process. Abort.");
            exit(1);
        }

        if (globcfg.pid > 0) {
            message(INFO, "---");
            message(INFO, "Success! Tuninetd has been started with PID: %i", globcfg.pid);
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
        message(INFO, "Started with pid %d", getpid());
    }
}

void version() {
    fprintf(stderr, VERSION);
}


void sighup_handler(int signo)
{
    if (status == OFF) {
       message(WARNING, "Warning! Tuninetd is already in standby mode.");
       return;
    }

    message(INFO, "SIGHUP caught, switch to standby mode.");

    switch_guard(OFF);
}

void sigusr_handler(int signo)
{
    long delta = 0;

    message(INFO, "SIGUSR1 caught:");

    if (globcfg.dev_name) {
        message(INFO, "- Capture engine: pcap, %s", globcfg.dev_name);
        if (globcfg.pcap_filter != NULL) {
            message(INFO, "-- Pcap filter: \"%s\"", globcfg.pcap_filter);
        }
    }

    if (globcfg.nf_group >= 0) {
        message(INFO, "- Capture engine: nflog group %ld", globcfg.nf_group);
    }

    message(INFO, "- cmd_path = %s", globcfg.cmd_path);
    message(INFO, "- TTL = %ld sec.", globcfg.ttl);

    if (status == OFF) {
        message(INFO, "- Current status: standby (OFF)");
    } else {
        delta = curts - ts;
        message(INFO, "- Current status: up (ON), time since last captured packet: %ld sec.", delta < 0 ? 0 : delta);
    }
}

void sigterm_handler(int signo)
{
    if (globcfg.nf_group >= 0) {
        xnflog_stop();
    }

    exit(0);
}

void usage(void) {
    fprintf(stderr, VERSION);
    fprintf(stderr, "\nEvent emitter with pcap and nflog sensors which could be used at the same time\n");
    fprintf(stderr, "\nUsage: \t%s -i <ifname> -c <path> [-f <filter>] [-n <nflog-group>] [-t <ttl>] [-d]\n", progname);
    fprintf(stderr, "\t%s -n <nflog-group> -c <path> [-i <ifname> [-f <filter>]] [-t <ttl>] [-d]\n", progname);
    fprintf(stderr, "\n\n");
    fprintf(stderr, "-i <ifname>: network interface to use with pcap. Must be up and configured.\n");
    fprintf(stderr, "-c <path>: to executable, will be run with 'start' and 'stop' parameter accordingly.\n");
    fprintf(stderr, "-n <nflog-group>: netfilter nflog group number (0 - 65535)\n");
    fprintf(stderr, "-f <filter>: specify pcap filter if needed, similar to tcpdump. Default none (all packets)\n");
    fprintf(stderr, "-t <ttl>: seconds of interface idle before 'stop' command will be run. Default 600.\n");
    fprintf(stderr, "-d: daemonize process. Check for errors before use.\n\n");
    fprintf(stderr, "-h: print this help\n\n");
    fprintf(stderr, "-v: print version\n\n");
    fprintf(stderr, "\nExamples:\n\n");
    fprintf(stderr, "# tuninetd -n 1 -c /path/to/executable/toggletunnel.sh\n");
    fprintf(stderr, "# tuninetd -i tap0 -c /path/to/executable/coolscript.sh\n");
    fprintf(stderr, "# tuninetd -i tun0 -f \"! host 1.2.3.4\" -c /path/to/executable/binary -t 3600 -d\n");
    fprintf(stderr, "# tuninetd -i enp3s0 -f \"arp and host 4.3.2.1\" -n 1 -c /path/to/executable/launcher.py\n\n");
    fprintf(stderr, "More information: https://github.com/root4root/tuninetd \n\n");
    exit(1);
}
