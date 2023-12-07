#ifndef TUNTAPD_H_
#define TUNTAPD_H_

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include <syslog.h>
#include <stdarg.h>
#include <signal.h>

#include "common.h"
#include "net.h"

#define VERSION "tuntapd 1.0.0\n"

static int tun_alloc(char *, int);
static void cread(int, char *, int);

static void build_config(int, char **);
static void check_config_and_daemonize();

static void sighup_handler(int);
static void sigusr_handler(int);
static void sigterm_handler(int);
static void usage(void);
static void version();

#endif /* TUNTAPD_H_ */
