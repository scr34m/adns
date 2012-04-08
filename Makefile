all:
	cc -Wall -s -O dns.c -o dns -lldns -L/usr/local/lib -I/usr/local/include

clean:
	rm -rf *.o dns
