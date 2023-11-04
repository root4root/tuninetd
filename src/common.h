#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdatomic.h>

#include "logger.h"

#define ON 1
#define OFF 0

//glob vars--
extern short int status;
extern atomic_ulong ts;     // @suppress("Type cannot be resolved")
extern unsigned long curts;

extern struct globcfg_t {
    short int isdaemon;
    pid_t pid;
    char *cmd_path;
    char *cmd_path_start;
    char *cmd_path_stop;
    char *pcap_filter;
    char *dev_name;
    long nf_group;
    int dev_mode;
    long ttl;
} globcfg; //--glob vars

//from thread.c--
void switch_guard(short action); //Used: tuninetd.c, xnflog.c, xpcap.c
void thread_init();              //Used: tuninetd.c
//--from thread.c

#endif
