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
    fprintf(stderr, "\nUsage:\n\n");
    fprintf(stderr, "%s -i <ifname> -c <path> [-m <iftype>] [-f <filter>] [-t <ttl>] [-d]\n", progname);
    fprintf(stderr, "\n\n");
    fprintf(stderr, "-i <ifname>: interface to use (tun or tap). Must be up and configured.\n");
    fprintf(stderr, "-c <path>: will be executed with 'start' and 'stop' parameter.\n");
    fprintf(stderr, "-m <iftype>: 'tun' or 'tap' mode. By default 'tun', should be set properly. \n");
    fprintf(stderr, "-f <filter>: specify pcap filter, similar to tcpdump\n");
    fprintf(stderr, "-t <ttl>: seconds of interface idle, before 'stop' command (default is 600).\n");
    fprintf(stderr, "-d: demonize process\n");
    fprintf(stderr, "-h: prints this help text\n\n");
    fprintf(stderr, "\nExample:\n\n");
    fprintf(stderr, "tuninetd -i tun0 -c /test/runtunnel.sh -f \"! host 1.2.3.4\" -t 3600 -d\n\n"); 
    exit(1);
}
