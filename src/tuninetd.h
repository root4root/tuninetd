#ifndef TUNINETD_H_
#define TUNINETD_H_

#include <signal.h>

#include "common.h"
#include "xnflog.h"

#define VERSION "tuninetd 1.5.RC\n"

void build_config(int, char **);
void check_config_and_daemonize();

void sighup_handler(int);
void sigusr_handler(int);
void sigterm_handler(int);

void version();
void usage();

#endif
