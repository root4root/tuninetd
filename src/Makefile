all: tuninetd
tuninetd: main.o nflog.o pcap.o thread.o tun.o utils.o
	[ -d ./bin ] || mkdir -p ./bin
	gcc main.o nflog.o pcap.o thread.o tun.o utils.o -o ./bin/tuninetd -lpthread -lpcap -lnetfilter_log
	
main.o: main.c main.h
	gcc -c main.c

nflog.o: nflog.c main.h
	gcc -c nflog.c
	
pcap.o: pcap.c main.h
	gcc -c pcap.c
	
thread.o: thread.c main.h
	gcc -c thread.c

tun.o: tun.c main.h
	gcc -c tun.c
	
utils.o: utils.c main.h
	gcc -c utils.c
	
clean:
	rm -f *.o tuninetd
	rm -rf ./bin