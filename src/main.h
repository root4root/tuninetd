#ifndef H_TUNINETD_MAIN
#define H_TUNINETD_MAIN

#include "common.h"
#include <signal.h>

void build_config(int, char **);
void check_config_and_daemonize();

#endif
