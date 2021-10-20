CFLAGS = -Wall -O2

all: tuninetd

tuninetd: main.o xnflog.o xpcap.o thread.o xtun.o utils.o
	[ -d ./bin ] || mkdir -p ./bin
	gcc main.o xnflog.o xpcap.o thread.o xtun.o utils.o -o ./bin/tuninetd -lpthread -lpcap -lnetfilter_log
	
main.o: main.c main.h common.h
	gcc $(CFLAGS) -c main.c

xnflog.o: xnflog.c common.h
	gcc $(CFLAGS) -c xnflog.c
	
xpcap.o: xpcap.c common.h
	gcc $(CFLAGS) -c xpcap.c
	
thread.o: thread.c common.h
	gcc $(CFLAGS) -c thread.c

xtun.o: xtun.c common.h
	gcc $(CFLAGS) -c xtun.c
	
utils.o: utils.c common.h
	gcc $(CFLAGS) -c utils.c
	
clean:
	rm -f *.o
	rm -rf ./bin
