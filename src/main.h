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
#include <signal.h>
#include <time.h>

#include <libnetfilter_log/libnetfilter_log.h>


#define BUFSIZE 2000
#define ON 1
#define OFF 0

int x, y;

short int debug = 0;
short int status = 0;
unsigned long ts = 0;
unsigned long curts = 0;

char progname[] = "tuninetd";

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

pthread_t pcap_x_thread;
pthread_t tun_x_thread;
pthread_t nflog_x_thread;
    
pthread_attr_t attr;
pthread_mutex_t lock;

void do_debug(char *msg, ...);
void my_err(char *msg, ...);
void my_info(char *msg, ...);
void switch_state(short action);
void switch_guard(short action);

void *tun_x(void *x_void_ptr);
void *nflog_x(void *x_void_ptr);
void *pcap_x(void *x_void_ptr);

#include "utils.c"
#include "tun.c"
#include "pcap.c"
#include "nflog.c"
