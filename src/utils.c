#include "main.h"
#include <syslog.h>
#include <stdarg.h>

static char progname[] = "tuninetd";

void do_debug(char *msg, ...)
{
    if(debug) {
        va_list argp;
        va_start(argp, msg);
        vfprintf(stderr, msg, argp);
        va_end(argp);
    }
}

void my_err(char *msg, ...) 
{
    va_list argp;
    va_start(argp, msg);
    
    if (globcfg.isdaemon == 0) {
        vfprintf(stderr, msg, argp);
        vfprintf(stderr, "\n", NULL);
    } else {
        openlog("tuninetd", 0, LOG_USER);
        vsyslog(LOG_ERR, msg, argp);
        closelog();
    }
    
    va_end(argp);
}

void my_info(char *msg, ...) 
{
    va_list argp;
    va_start(argp, msg);
    
    if (globcfg.isdaemon == 0) {
        vfprintf(stderr, msg, argp);
        vfprintf(stderr, "\n", NULL);
    } else {
        openlog("tuninetd", 0, LOG_USER);
        vsyslog(LOG_INFO, msg, argp);
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
    fprintf(stderr, "-d: demonize process. Check for errors before use.\n\n");
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


void sig_handler(int signo)
{
    if (status == OFF) {
       my_err("Warning! Tuninetd is already in standby mode.");
       return;
    }
    
    my_info("SIGHUP caught. Going to standby mode.");
    
    switch_guard(OFF);
}
