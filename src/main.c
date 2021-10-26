#include "main.h"

int main(int argc, char *argv[])
{
    curts = time(NULL);

    build_config(argc, argv);
    check_config_and_daemonize();
    thread_init(); //Initialize our workers (thread.c)

    struct timespec tim;

    tim.tv_sec = 1;
    tim.tv_nsec = 0;

    //debug = 1;
    
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
    static const char *optString = "i:t:c:f:m:n:dhv";

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

        opt = getopt(argc, argv, optString);
    }
}

void check_config_and_daemonize()
{
    if (globcfg.dev_name == NULL && globcfg.nf_group < 0) {
        message(ERROR, "tun/tap device OR nfgroup must be specified. Abort.");
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

        chdir("/");

        setsid();

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    } else {
        message(INFO, "Started with pid %d", getpid());
    }
}
