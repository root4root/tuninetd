#include "main.h"

int main(int argc, char *argv[])
{
    int opt = 0;
    
    struct timespec tim;

    //debug = 1;

    tim.tv_sec = 1;
    tim.tv_nsec = 0;
   
    static const char *optString = "i:t:c:f:m:n:dhv";
  
    curts = time(NULL);
    
    globcfg.isdaemon = 0;
    globcfg.pid = 0;
    globcfg.cmd_path = NULL;
    globcfg.ttl = 600;
    globcfg.dev_mode = IFF_TUN;
    globcfg.nf_group = -1;
    
    opt = getopt( argc, argv, optString);
    
    while( opt != -1 ) {
        switch( opt ) {
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
                
            case 'f':
                globcfg.pcap_filter = optarg;
                break;
            case 'm':
                if (strcmp("tap", optarg)== 0) {
                    globcfg.dev_mode = IFF_TAP;
                }
                break;
            case 'n':
                globcfg.nf_group = atoi(optarg);
                break;
            case 'd':
                globcfg.isdaemon = 1;
                break;
            case 'h':   //go to the next case, same behaviour.
            case '?':
                usage();
                break;
            default:
                exit(1);
                break;
        }
         
        opt = getopt( argc, argv, optString );
    }
    
    if (globcfg.dev_name == NULL && globcfg.nf_group < 0) {
        my_err("tun/tap device OR nfgroup must be specified.");
        usage();
        exit(1);
    }
    
    if (globcfg.cmd_path == NULL) {
        my_err("Executable path must be specified");
        usage();
        exit(1);
    }
    
    
    if (globcfg.isdaemon == 1) {
        globcfg.pid = fork();
        
        if (globcfg.pid < 0) {
            my_err("Can't fork process. Abort.");
            exit(1);
        }

        if (globcfg.pid > 0) {
            my_info("---");
            my_info("Success! tuninetd has been started with pid: %i", globcfg.pid);
            exit(0);
        }

        chdir("/");
        
        setsid();
       
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    } else 
        my_info("Started with pid %d", getpid());    
    
    thread_init(); //Initialization our workers (thread.c)
    
    if (signal(SIGHUP, sig_handler) == SIG_ERR)
         my_info("Can't catch SIGHUP\n");
    
    
    while (1) {
    
        nanosleep(&tim, NULL); //Tick
        
        curts = time(NULL);
        //do_debug("Tick %lu ...\n", curts);//
       
        if (ts != 0 && status == 1 && ((curts - ts) >= globcfg.ttl) ) {
            my_info("CORE: executing STOP command...");
            switch_guard(OFF);
        }
    }
    
    free(globcfg.cmd_path_start);
    free(globcfg.cmd_path_stop);
    
    return 0;
}
