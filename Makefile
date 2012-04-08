CC=cc
LDFLAGS= -lldns -lmemcache -L/usr/local/lib
CFLAGS=-c -Wall -I/usr/local/include

all:	dns

dns:	dns.o
	$(CC) $(LDFLAGS) dns.o -o dns

dns.o:	dns.c
	$(CC) $(CFLAGS) dns.c

clean:
	rm -rf *.o dns
