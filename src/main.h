#ifndef H_TUNINETD_MAIN
#define H_TUNINETD_MAIN

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#define BUFSIZE 2000
#define ON 1
#define OFF 0
#define VERSION "\ntuninetd 1.2.1\n"

//global vars.
short int debug;
short int status;
unsigned long ts;
unsigned long curts;

struct globcfg_t {
    short int isdaemon;
    pid_t pid;
    char *cmd_path;
    char *cmd_path_start;
    char *cmd_path_stop;
    char *pcap_filter;
    char *dev_name;
    long nf_group;
    int dev_mode;
    int ttl;
} globcfg;

    
//from utils.c
void do_debug(char *msg, ...);
void my_err(char *msg, ...);
void my_info(char *msg, ...);
void sig_handler(int signo);
void usage();
void version();

//from thread.c
void switch_guard(short action);
void thread_init();

void *tun_x(void *x_void_ptr);
void *nflog_x(void *x_void_ptr);
void *pcap_x(void *x_void_ptr);

#endif
