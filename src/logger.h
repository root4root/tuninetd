#ifndef LOGGER_H_
#define LOGGER_H_

#include "net.h"

#define ERROR 0
#define WARNING 1
#define INFO 2

void do_debug(const char *, ...);
void message(int, const char *, ...);
void log_packet(const packet *);
int init_pcap_file(const char *);

#endif /* LOGGER_H_ */
