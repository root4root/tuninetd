//Author: root4root@gmail.com

#include <fcntl.h>
#include <pthread.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>

#define BUFSIZE 2000

int debug = 0;
int status = 0;
long ts = 0;
long curts = 0;

char progname[] = "tuninetd";

struct globcfg_t {
    int isdaemon;
    pid_t pid;
    char *cmd_path;
    char *cmd_path_start;
    char *cmd_path_stop;
    char *pcap_filter;
    char *dev_name;
    int dev_mode;
    int ttl;
} globcfg;

#include "utils.c"
#include "tun.c"
#include "pcap.c"

int main(int argc, char *argv[])
{
    int x, y, opt=0;
   
    static const char *optString = "i:t:c:f:m:dh";
  
    curts = time(NULL);
    
    globcfg.isdaemon = 0;
    globcfg.pid = 0;
    globcfg.cmd_path = NULL;
    globcfg.ttl = 600;
    globcfg.dev_mode = IFF_TUN;
    
    opt = getopt( argc, argv, optString);
    
    while( opt != -1 ) {
        switch( opt ) {
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
            case 'd':
                globcfg.isdaemon = 1;
                break;
            case 'h':   /* намеренный проход в следующий case-блок */
            case '?':
                usage();
                break;
            default:
                exit(1);
                break;
        }
         
        opt = getopt( argc, argv, optString );
    }
    
    if (globcfg.dev_name == NULL) {
        my_err("tun/tap device must be specified with proper type (-m by default tun).");
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
    }
    
    pthread_t inc_x_thread;
    pthread_t tun_x_thread;
    
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    
    pthread_create(&inc_x_thread, &attr, inc_x, &x);
    pthread_create(&tun_x_thread, &attr, tun_x, &y);
   
    while (1) {
        usleep(1000000);
        curts = time(NULL);
       
        if (ts != 0 && status == 1 && ((curts - ts) >= globcfg.ttl) ) {
           status = 0;
           my_info("Executing STOP command... Binding again to interface %s", globcfg.dev_name);
           
            if (system(globcfg.cmd_path_stop) != 0) {
                my_err("Warning! Executable command doesn't return 0 (%s)", globcfg.cmd_path_stop);
            }
           
           pthread_create(&tun_x_thread, &attr, tun_x, &y);
        }
    }
    return 0;
}
