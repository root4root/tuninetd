all: default
default: main.c
	[ -d ./bin ] || mkdir -p ./bin
	gcc -o ./bin/tuninetd main.c -lpthread -lpcap -lnetfilter_log
clean:
	rm -rf ./bin