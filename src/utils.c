#include "common.h"
#include <syslog.h>
#include <stdarg.h>

static char progname[] = "tuninetd";

void do_debug(const char *msg, ...)
{
    if(debug) {
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

void usage(void) {
    fprintf(stderr, VERSION);
    fprintf(stderr, "\nUsage:\n\n");
    fprintf(stderr, "%s {-i <ifname> | -n <nflog-group>} -c <path> [-m <iftype>] [-f <filter>] [-t <ttl>] [-d]\n", progname);
    fprintf(stderr, "\n\n");
    fprintf(stderr, "-i <ifname>: interface to use (tun or tap). Must be up and configured.\n");
    fprintf(stderr, "-c <path>: will be executed with 'start' and 'stop' parameter accordingly.\n");
    fprintf(stderr, "-m <iftype>: 'tun' or 'tap' mode. By default 'tun'. \n");
    fprintf(stderr, "-n <nflog-group>: NFLOG group number ('-i', '-m' and '-f' will be ignored in this case.) \n");
    fprintf(stderr, "-f <filter>: specify pcap filter, similar to tcpdump.\n");
    fprintf(stderr, "-t <ttl>: interface idling in seconds, before 'stop' command will be launched. 600 by default.\n");
    fprintf(stderr, "-d: daemonize process. Check for errors before use.\n\n");
    fprintf(stderr, "-h: print this help\n\n");
    fprintf(stderr, "-v: print version\n\n");
    fprintf(stderr, "\nExamples:\n\n");
    fprintf(stderr, "# tuninetd -i tun0 -c /test/runtunnel.sh -f \"! host 1.2.3.4\" -t 3600 -d\n");
    fprintf(stderr, "# tuninetd -n 1 -c /etc/tuninetd/toggletunnel.sh -d\n\n");
    exit(1);
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
    if (globcfg.nf_group < 0) {
        message(INFO, "- Capture engine: pcap + tun/tap");
        if (globcfg.pcap_filter != NULL) {
            message(INFO, "-- Pcap filter: \"%s\"", globcfg.pcap_filter);
        }
    } else {
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
