#include <stdarg.h>
#include <syslog.h>

#include "common.h"

#define DEBUG_MODE 0

void do_debug(const char *msg, ...)
{
    if (DEBUG_MODE) {
        va_list argp;
        va_start(argp, msg);
        vfprintf(stderr, msg, argp);
        va_end(argp);
    }
}

void message(int mylogpriority, const char *msg, ...)
{
    int syslogpriority;

    if (mylogpriority == ERROR) {
        syslogpriority = LOG_ERR;
    } else if (mylogpriority == WARNING) {
        syslogpriority = LOG_WARNING;
    } else {
        syslogpriority = LOG_INFO;
    }

    va_list argp;
    va_start(argp, msg);

    if (globcfg.isdaemon == 0) {
        vfprintf(stderr, msg, argp);
        vfprintf(stderr, "\n", NULL);
    } else {
        openlog("tuninetd", 0, LOG_USER);
        vsyslog(syslogpriority, msg, argp);
        closelog();
    }

    va_end(argp);
}
