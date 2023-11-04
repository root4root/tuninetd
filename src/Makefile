COMPILER = gcc
CFLAGS = -Wall -O2

all: tuninetd tuntapd

tuninetd: tuninetd.o xnflog.o xpcap.o thread.o logger.o net.o
	[ -d ./bin ] || mkdir -p ./bin
	$(COMPILER) tuninetd.o xnflog.o xpcap.o thread.o logger.o net.o -o ./bin/tuninetd -lpthread -lpcap -lnetfilter_log -lnfnetlink
	
tuninetd.o: tuninetd.c tuninetd.h common.h
	$(COMPILER) $(CFLAGS) -c tuninetd.c

xnflog.o: xnflog.c common.h
	$(COMPILER) $(CFLAGS) -c xnflog.c
	
xpcap.o: xpcap.c common.h
	$(COMPILER) $(CFLAGS) -c xpcap.c
	
thread.o: thread.c common.h
	$(COMPILER) $(CFLAGS) -c thread.c

logger.o: logger.c logger.h
	$(COMPILER) $(CFLAGS) -c logger.c
	
net.o: net.c net.h
	$(COMPILER) $(CFLAGS) -c net.c
	
tuntapd: tuntapd.o logger.o net.o
	$(COMPILER) tuntapd.o logger.o net.o -o ./bin/tuntapd
	
tuntapd.o: tuntapd.c tuntapd.h
	$(COMPILER) $(CFLAGS) -c tuntapd.c 
	
clean:
	rm -f *.o
	rm -rf ./bin
