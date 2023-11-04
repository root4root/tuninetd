#ifndef LOGGER_H_
#define LOGGER_H_

#define ERROR 0
#define WARNING 1
#define INFO 2

void do_debug(const char *, ...);
void message(int, const char *, ...);


#endif /* LOGGER_H_ */
