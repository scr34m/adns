/*
telnet 127.0.0.1 11211

/usr/bin/printf "set 2y.hu 0 0 12 0\r\n78.47.162.53\r\nquit" | nc 127.0.0.1 11211
/usr/bin/printf "set ns1.2y.hu 0 0 12 0\r\n78.47.162.53\r\nquit" | nc 127.0.0.1 11211
/usr/bin/printf "set www.2y.hu 0 0 12 0\r\n78.47.162.53\r\nquit" | nc 127.0.0.1 11211
/usr/bin/printf "set update.2y.hu 0 0 12 0\r\n78.47.162.53\r\nquit" | nc 127.0.0.1 11211
/usr/bin/printf "set ns2.2y.hu 0 0 12 0\r\n78.47.207.93\r\nquit" | nc 127.0.0.1 11211

get 2y.hu
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/if_types.h>
#include <errno.h>

#include <ldns/ldns.h>
#include <memcache.h>

#define INBUF_SIZE	(4096)
#define MAXLINE		(256)

// nencache
struct memcache *mc;
char *mc_instance = "127.0.0.1:11211";

// socket
int so;
struct sockaddr paddr;
socklen_t plen = (socklen_t) sizeof(paddr);
u_int16_t port = 53;

// misc
int debug = 0;

volatile sig_atomic_t   stop;

void sighdlr(int sig)
{
	switch (sig)
	{
		case SIGINT:
		case SIGTERM:
			stop = 1;
			break;
		case SIGHUP:
			break;
		case SIGCHLD:
			break;
	}
}

void installsignal(int sig, char *name)
{
	struct sigaction	sa;
	char			msg[80];

	sa.sa_handler = sighdlr;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(sig, &sa, NULL) == -1)
	{
		snprintf(msg, sizeof msg, "could not install %s handler", name);
		printf(msg);
		exit(1);
	}
}

int udp_bind(int sock, u_int16_t port, char *my_address)
{
	struct sockaddr_in addr;
	in_addr_t maddr = INADDR_ANY;

	if (my_address)
		if (inet_pton(AF_INET, my_address, &maddr) < 1)
			return (EINVAL);

	addr.sin_family = AF_INET;
	addr.sin_port = (in_port_t) htons((uint16_t)port);
	addr.sin_addr.s_addr = maddr;
	return (bind(sock, (struct sockaddr *)&addr, (socklen_t) sizeof(addr)));
}

void logpacket(ldns_pkt *pkt)
{
	char *str = ldns_pkt2str(pkt);

	if (str)
		printf("%s\n", str);
	else
		printf("could not convert packet to string\n");
	LDNS_FREE(str);
}

char * hostnamefrompkt(ldns_pkt *pkt, ldns_rr **qrr)
{
	ldns_rr			*query_rr;
	char			*name = NULL, *rawname = NULL;
	ssize_t			len;
	int			i, found;

	if (pkt == NULL)
		return (NULL);

	query_rr = ldns_rr_list_rr(ldns_pkt_question(pkt), 0);
	rawname = ldns_rr2str(query_rr);
	if (rawname == NULL)
	{
		return (name);
	}

	len = strlen(rawname);
	if (len <= 2)
	{
		free(rawname);
		return (name);
	}

	len -= 2;

	/* strip off everything past last .*/
	for (i = 0, found = 0; i < len; i++)
	{
		if (rawname[i] == '.' && isblank(rawname[i + 1]))
		{
			found = 1;
			break;
		}
	}

	if (found)
	{
		rawname[i] = '\0';
		if (asprintf(&name, "%s", rawname) == -1)
		{
			name = NULL;
			free(rawname);
			return (name);
		}
		if (qrr)
		{
			*qrr = query_rr;
		}
	}

	free(rawname);
	return (name);
}

int answerquery(char *hn, char *ip, ldns_rr *query_rr, u_int16_t id)
{
	ldns_status		status;
	ldns_rr_list		*answer_a = NULL;
	ldns_rr_list		*answer_ns1 = NULL;
	ldns_rr_list		*answer_ns2 = NULL;
//	ldns_rr_list		*answer_cname = NULL;
//	ldns_rr_list		*answer_mx = NULL;
	ldns_rr_list		*answer_soa = NULL;
	ldns_rr_list		*answer_qr = NULL;
	ldns_pkt		*answer_pkt = NULL;
	ldns_rr			*myrr = NULL;
	ldns_rdf		*prev = NULL;
	ldns_rr_type	type;
	char			buf[MAXLINE * 2];
	size_t			answer_size;
	uint8_t			*outbuf = NULL;
	int			rv = 1;
	char			*ipaddr = NULL, *hostname = NULL;

	ipaddr = ip;
	hostname = hn;
	type = ldns_rr_get_type(query_rr);

	/* ns & soa for authority */
	answer_ns1 = ldns_rr_list_new();
	if (answer_ns1 == NULL)
		goto unwind;

	snprintf(buf, sizeof buf, "%s.\t%d\tIN\tNS\tns1.2y.hu.", hostname, 60);
	status = ldns_rr_new_frm_str(&myrr, buf, 0, NULL, &prev);
	if (status != LDNS_STATUS_OK)
	{
		fprintf(stderr, "can't create authority section: %s\n", ldns_get_errorstr_by_id(status));
		goto unwind;
	}
	ldns_rr_list_push_rr(answer_ns1, myrr);
	ldns_rdf_deep_free(prev);
	prev = NULL;

	answer_ns2 = ldns_rr_list_new();
	if (answer_ns2 == NULL)
		goto unwind;

	snprintf(buf, sizeof buf, "%s.\t%d\tIN\tNS\tns2.2y.hu.", hostname, 60);
	status = ldns_rr_new_frm_str(&myrr, buf, 0, NULL, &prev);
	if (status != LDNS_STATUS_OK)
	{
		fprintf(stderr, "can't create authority section: %s\n", ldns_get_errorstr_by_id(status));
		goto unwind;
	}
	ldns_rr_list_push_rr(answer_ns2, myrr);
	ldns_rdf_deep_free(prev);
	prev = NULL;

	answer_soa = ldns_rr_list_new();
	if (answer_soa == NULL)
		goto unwind;

	snprintf(buf, sizeof buf, "2y.hu.\t1800\tIN\tSOA\tns1.2y.hu. hostmaster.deeb.hu. 1340305068 900 300 604800 1800");
	status = ldns_rr_new_frm_str(&myrr, buf, 0, NULL, &prev);
	if (status != LDNS_STATUS_OK)
	{
		fprintf(stderr, "can't create authority section: %s\n", ldns_get_errorstr_by_id(status));
		goto unwind;
	}
	ldns_rr_list_push_rr(answer_soa, myrr);
	ldns_rdf_deep_free(prev);
	prev = NULL;

	if (ipaddr && (type == LDNS_RR_TYPE_A || type == LDNS_RR_TYPE_ANY))
	{
		answer_a = ldns_rr_list_new();
		if (answer_a == NULL)
			goto unwind;

		snprintf(buf, sizeof buf, "%s.\t%d\tIN\tA\t%s", hostname, 60, ipaddr);
		status = ldns_rr_new_frm_str(&myrr, buf, 0, NULL, &prev);
		if (status != LDNS_STATUS_OK)
		{
			fprintf(stderr, "can't create answer section: %s\n", ldns_get_errorstr_by_id(status));
			goto unwind;
		}
		ldns_rr_list_push_rr(answer_a, myrr);
		ldns_rdf_deep_free(prev);
		prev = NULL;
	}

	if (type == LDNS_RR_TYPE_CNAME || type == LDNS_RR_TYPE_ANY)
	{
	}

	if (type == LDNS_RR_TYPE_MX || type == LDNS_RR_TYPE_ANY)
	{
	}

	if (type == LDNS_RR_TYPE_SOA)
	{

	}

	/* question section */
	answer_qr = ldns_rr_list_new();
	if (answer_qr == NULL)
		goto unwind;
	ldns_rr_list_push_rr(answer_qr, ldns_rr_clone(query_rr));

	/* actual packet */
	answer_pkt = ldns_pkt_new();
	if (answer_pkt == NULL)
		goto unwind;
	
	ldns_pkt_set_qr(answer_pkt, 1);
	ldns_pkt_set_aa(answer_pkt, 1);
	ldns_pkt_set_id(answer_pkt, id);

	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_QUESTION, answer_qr);

	if (answer_soa && type == LDNS_RR_TYPE_ANY)
		ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ANSWER, answer_soa);
	if (answer_ns1 && type == LDNS_RR_TYPE_ANY)
		ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ANSWER, answer_ns1);
	if (answer_ns2 && type == LDNS_RR_TYPE_ANY)
		ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ANSWER, answer_ns2);
	if (answer_a)
		ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ANSWER, answer_a);
	if (answer_ns1 && type == LDNS_RR_TYPE_NS)
		ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ANSWER, answer_ns1);
	if (answer_ns2 && type == LDNS_RR_TYPE_NS)
		ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ANSWER, answer_ns2);
	if (answer_soa && type == LDNS_RR_TYPE_SOA)
		ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ANSWER, answer_soa);

	// XXX no record (A,MX,NS,CNAME) then authority is SOA not NS

	if (answer_ns1 && (type != LDNS_RR_TYPE_ANY && type != LDNS_RR_TYPE_NS))
		ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_AUTHORITY, answer_ns1);
	if (answer_ns2 && (type != LDNS_RR_TYPE_ANY && type != LDNS_RR_TYPE_NS))
		ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_AUTHORITY, answer_ns2);

	status = ldns_pkt2wire(&outbuf, answer_pkt, &answer_size);
	if (status != LDNS_STATUS_OK)
	{
		printf("can't create answer: %s\n", ldns_get_errorstr_by_id(status));
	} else
	{
		if (debug) {
			printf("answerquery response:\n");
			logpacket(answer_pkt);
		}

		if (sendto(so, outbuf, answer_size, 0, &paddr, plen) == -1)
		{
			printf("answerquery sendto error\n");
		} else
		{
			rv = 0;
			printf("answerquery %s to %s\n", hostname, inet_ntoa( ((struct sockaddr_in *) &paddr)->sin_addr));
		}
	}

unwind:
	if (answer_pkt)
		ldns_pkt_free(answer_pkt);
	if (outbuf)
		LDNS_FREE(outbuf);
	if (answer_qr)
		ldns_rr_list_free(answer_qr);
	if (answer_a)
		ldns_rr_list_free(answer_a);
	if (answer_ns1)
		ldns_rr_list_free(answer_ns1);
	if (answer_ns2)
		ldns_rr_list_free(answer_ns2);
	if (answer_soa)
		ldns_rr_list_free(answer_soa);

	return (rv);
}

int nxdomain(char *hn, ldns_rr *query_rr, u_int16_t id)
{
	ldns_status		status;
	ldns_rr_list		*answer_qr = NULL;
	ldns_pkt		*answer_pkt = NULL;
	uint8_t			*outbuf = NULL;
	size_t			answer_size;
	int			rv = 1;
	char		*hostname = NULL;

	hostname = hn;

	/* question section */
	answer_qr = ldns_rr_list_new();
	if (answer_qr == NULL)
		goto unwind;
	ldns_rr_list_push_rr(answer_qr, ldns_rr_clone(query_rr));

	/* actual packet */
	answer_pkt = ldns_pkt_new();
	if (answer_pkt == NULL)
		goto unwind;
	
	ldns_pkt_set_qr(answer_pkt, 1);
	ldns_pkt_set_aa(answer_pkt, 1);
	ldns_pkt_set_id(answer_pkt, id);

	ldns_pkt_set_rcode(answer_pkt, LDNS_RCODE_NXDOMAIN);

	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_QUESTION, answer_qr);

	status = ldns_pkt2wire(&outbuf, answer_pkt, &answer_size);
	if (status != LDNS_STATUS_OK)
	{
		printf("can't create answer: %s\n", ldns_get_errorstr_by_id(status));
	} else
	{
		if (debug) {
			printf("answerquery response:\n");
			logpacket(answer_pkt);
		}

		if (sendto(so, outbuf, answer_size, 0, &paddr, plen) == -1)
		{
			printf("answerquery sendto error\n");
		} else
		{
			rv = 0;
			printf("answerquery %s to NXdomain\n", hostname);
		}
	}

unwind:
	if (answer_pkt)
		ldns_pkt_free(answer_pkt);
	if (outbuf)
		LDNS_FREE(outbuf);
	if (answer_qr)
		ldns_rr_list_free(answer_qr);

	return (rv);
}

void setupmemcache()
{
	mc = mc_new();
	mc_server_add4(mc, mc_instance);
}

int main(int argc, char *argv[])
{
	uint8_t inbuf[INBUF_SIZE];
	char *listen_addr = "0.0.0.0";
	ssize_t nb;
	ldns_status status;
	ldns_pkt *query_pkt;
	ldns_rr *query_rr;
	char *hostname;
	u_int16_t id;
	char buf[MAXLINE * 2];

	char c;
	while ((c = getopt (argc, argv, "dp:l:m:")) != -1)
	{
		switch (c) 
		{
			case 'd':
				debug = 1;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'l':
				listen_addr = optarg;
				break;
			case 'm':
				mc_instance = optarg;
				break;
			case '?':
				if (optopt == 'c')
					fprintf(stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf(stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
				return 1;
			default:
				abort();
		}
	}

	printf("listen = %s, port = %d, memcache: %s\n", listen_addr, port, mc_instance);

	so = socket(AF_INET, SOCK_DGRAM, 0);
	if (so == -1)
		err(1, "can't open socket");

	if (udp_bind(so, port, listen_addr))
		err(1, "can't udp bind");

	setupmemcache();

	installsignal(SIGCHLD, "CHLD");
	installsignal(SIGTERM, "TERM");
	installsignal(SIGUSR1, "USR1");
	installsignal(SIGHUP, "HUP");

	while (!stop)
	{
		nb = recvfrom(so, inbuf, INBUF_SIZE, 0, &paddr, &plen);
		if (nb == -1)
		{
			if (errno == EINTR || errno == EAGAIN)
			{
				continue;
			}
			err(1, "recvfrom");
		}

		status = ldns_wire2pkt(&query_pkt, inbuf, (size_t)nb);
		if (status != LDNS_STATUS_OK)
		{
			printf("bad packet: %s\n", ldns_get_errorstr_by_id(status));
			continue;
		}

		if (debug)
		{
			printf("received packet:\n");
			logpacket(query_pkt);
		}

		hostname = hostnamefrompkt(query_pkt, &query_rr);
		if (hostname == NULL)
		{
			continue;
		}

		printf("query for: %s IN ", hostname);
		ldns_rr_type type = ldns_rr_get_type(query_rr);
		switch (type)
		{
			case LDNS_RR_TYPE_A:
				printf("A\n");
				break;
			case LDNS_RR_TYPE_CNAME:
				printf("CNAME\n");
				break;
			case LDNS_RR_TYPE_MX:
				printf("MX\n");
				break;
			case LDNS_RR_TYPE_NS:
				printf("NS\n");
				break;
			case LDNS_RR_TYPE_SOA:
				printf("SOA\n");
				break;
			default:
				printf("unknow %d\n", type);
				break;
		}

		id = ldns_pkt_id(query_pkt);

		char *ret = mc_aget(mc, hostname, strlen(hostname));
		if (ret)
		{
			snprintf(buf, sizeof buf, "%s", ret);
			free(ret);

			answerquery(hostname, &buf, query_rr, id);
		} else {
			nxdomain(hostname, query_rr, id);
		}

		free(hostname);
		ldns_pkt_free(query_pkt);

	}

	return 0;
}
