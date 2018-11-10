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
    fprintf(stderr, "%s {-i <ifname> | -n <nflog-group>} -c <path> [-m <iftype>] [-f <filter>] [-t <ttl>] [-d]\n", progname);
    fprintf(stderr, "\n\n");
    fprintf(stderr, "-i <ifname>: interface to use (tun or tap). Must be up and configured.\n");
    fprintf(stderr, "-c <path>: will be executed with 'start' and 'stop' parameter.\n");
    fprintf(stderr, "-m <iftype>: 'tun' or 'tap' mode. By default 'tun', should be set properly. \n");
    fprintf(stderr, "-n <nflog-group>: NFLOG group number. If it sets, '-i', '-m' and '-f' flags will be ignored. \n");
    fprintf(stderr, "-f <filter>: specify pcap filter, similar to tcpdump\n");
    fprintf(stderr, "-t <ttl>: seconds of interface idle, before 'stop' command (default is 600).\n");
    fprintf(stderr, "-d: demonize process\n");
    fprintf(stderr, "-h: prints this help text\n\n");
    fprintf(stderr, "\nExample:\n\n");
    fprintf(stderr, "tuninetd -i tun0 -c /test/runtunnel.sh -f \"! host 1.2.3.4\" -t 3600 -d\n\n"); 
    exit(1);
}

void switch_state(short action)
{
    if (status == action) {
        return;
    }
    
    ts = time(NULL);
    
    if (action == ON) {
        if (system(globcfg.cmd_path_start) != 0) 
            my_err("Warning! Executable command doesn't return 0 (%s)", globcfg.cmd_path_start);
        
        status = ON;
        
    } else {
        if (system(globcfg.cmd_path_stop) != 0)
            my_err("Warning! Executable command doesn't return 0 (%s)", globcfg.cmd_path_stop);
        
        status = OFF;
        
        if (globcfg.nf_group < 0) 
            pthread_create(&tun_x_thread, &attr, tun_x, &y);
        
    }
    
}

void switch_guard(short action)
{
    pthread_mutex_lock(&lock);
    switch_state(action);
    pthread_mutex_unlock(&lock);
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
