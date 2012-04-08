#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include <sys/types.h>
#include <sys/socket.h>
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

// socket
int so;
struct sockaddr paddr;
socklen_t plen = (socklen_t) sizeof(paddr);
u_int16_t port = 53;

// resolver
ldns_resolver *resolver;
char *domainname;
char *resolv_conf;

// misc
int debug = 0;

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

int spoofquery(char *hn, char *ip, ldns_rr *query_rr, u_int16_t id)
{
	ldns_status		status;
	ldns_rr_list		*answer_an = NULL;
	ldns_rr_list		*answer_ns = NULL;
	ldns_rr_list		*answer_ad = NULL;
	ldns_rr_list		*answer_qr = NULL;
	ldns_pkt		*answer_pkt = NULL;
	ldns_rr			*myrr = NULL, *myaurr = NULL;
	ldns_rdf		*prev = NULL;
	char			buf[MAXLINE * 2];
	size_t			answer_size;
	uint8_t			*outbuf = NULL;
	int			rv = 1;
	char			*ipaddr = NULL, *hostname = NULL;

	ipaddr = ip;
	hostname = hn;

	/* answer section */
	answer_an = ldns_rr_list_new();
	if (answer_an == NULL)
		goto unwind;

	/* authority section */
	answer_ns = ldns_rr_list_new();
	if (answer_ns == NULL)
		goto unwind;

	/* if we have an ip spoof it there */
	if (ipaddr)
	{
		/* an */
		snprintf(buf, sizeof buf, "%s.\t%d\tIN\tA\t%s", hostname, 259200, ipaddr);
		status = ldns_rr_new_frm_str(&myrr, buf, 0, NULL, &prev);
		if (status != LDNS_STATUS_OK)
		{
			fprintf(stderr, "can't create answer section: %s\n", ldns_get_errorstr_by_id(status));
			goto unwind;
		}
		ldns_rr_list_push_rr(answer_an, myrr);
		ldns_rdf_deep_free(prev);
		prev = NULL;

		/* ns */
		snprintf(buf, sizeof buf, "%s.\t%d\tIN\tNS\t127.0.0.1.", hostname, 259200);
		status = ldns_rr_new_frm_str(&myaurr, buf, 0, NULL, &prev);
		if (status != LDNS_STATUS_OK)
		{
			fprintf(stderr, "can't create authority section: %s\n", ldns_get_errorstr_by_id(status));
			goto unwind;
		}
		ldns_rr_list_push_rr(answer_ns, myaurr);
		ldns_rdf_deep_free(prev);
		prev = NULL;
	}

	/* question section */
	answer_qr = ldns_rr_list_new();
	if (answer_qr == NULL)
		goto unwind;
	ldns_rr_list_push_rr(answer_qr, ldns_rr_clone(query_rr));

	/* additional section */
	answer_ad = ldns_rr_list_new();
	if (answer_ad == NULL)
		goto unwind;

	/* actual packet */
	answer_pkt = ldns_pkt_new();
	if (answer_pkt == NULL)
		goto unwind;
	
	ldns_pkt_set_qr(answer_pkt, 1);
	ldns_pkt_set_aa(answer_pkt, 1);
	ldns_pkt_set_id(answer_pkt, id);
	if (ipaddr == NULL)
		ldns_pkt_set_rcode(answer_pkt, LDNS_RCODE_NXDOMAIN);

	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_QUESTION, answer_qr);
	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ANSWER, answer_an);
	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_AUTHORITY, answer_ns);
	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ADDITIONAL, answer_ad);

	status = ldns_pkt2wire(&outbuf, answer_pkt, &answer_size);
	if (status != LDNS_STATUS_OK)
		printf("can't create answer: %s\n",
		    ldns_get_errorstr_by_id(status));
	else {
		if (debug) {
			printf("spoofquery response:\n");
			logpacket(answer_pkt);
		}

		if (sendto(so, outbuf, answer_size, 0, &paddr, plen) == -1)
			printf("spoofquery sendto\n");
		else {
			rv = 0;
			printf("spoofquery: spoofing %s to %s\n", hostname, ipaddr ? ipaddr : "NXdomain");
		}
	}

unwind:
	if (answer_pkt)
		ldns_pkt_free(answer_pkt);
	if (outbuf)
		LDNS_FREE(outbuf);
	if (answer_qr)
		ldns_rr_list_free(answer_qr);
	if (answer_an)
		ldns_rr_list_free(answer_an);
	if (answer_ns)
		ldns_rr_list_free(answer_ns);
	if (answer_ad)
		ldns_rr_list_free(answer_ad);

	return (rv);
}

int forwardquery(char *hostname, ldns_rr *query_rr, u_int16_t id)
{
	size_t answer_size;
	u_int16_t qflags = LDNS_RD;
	uint8_t *outbuf = NULL;
	ldns_rdf *qname = NULL;
	ldns_pkt *respkt = NULL;
	ldns_rr_type type;
	ldns_rr_class clas;
	ldns_status status;
	int rv = 1, child = 0;

	switch (fork())
	{
		case -1:
			printf("cannot fork\n");
			break;
		case 0:
			child = 1;
			break;
		default:
			return (0);
	}

	qname = ldns_dname_new_frm_str(hostname);
	if (!qname)
	{
		printf("forwardquery: can't make qname\n");
		goto unwind;
	}
	type = ldns_rr_get_type(query_rr);
	clas = ldns_rr_get_class(query_rr);
	respkt = ldns_resolver_query(resolver, qname, type, clas, qflags);
	if (respkt == NULL)
	{
		/* dns query failed so lets spoof it instead of timing out */
		printf("forwardquery: query failed, spoofing response\n");

		/* XXX make this tunable? */
		spoofquery(hostname, NULL, query_rr, id);
		goto unwind;
	}
	if (debug)
	{
		printf("forwardquery response:\n");
		logpacket(respkt);
	}

	ldns_pkt_set_id(respkt, id);
	status = ldns_pkt2wire(&outbuf, respkt, &answer_size);
	if (status != LDNS_STATUS_OK)
		printf("can't create answer: %s\n",
		    ldns_get_errorstr_by_id(status));
	else {
		if (sendto(so, outbuf, answer_size, 0, &paddr, plen) == -1)
			printf("forwardquery sendto\n");
		else {
			rv = 0;
			printf("forwardquery: resolved %s\n", hostname);
		}
	}

unwind:
	if (respkt)
		ldns_pkt_free(respkt);
	if (outbuf)
		LDNS_FREE(outbuf);
	if (qname)
		ldns_rdf_free(qname);

	if (child)
		_exit(0);

	return (rv);
}

void setupresolver(void)
{
	ldns_status		status;
	char			*action = "using", *es;
	char			buf[128];
	ldns_rdf		*dn;
	size_t			i;

	if (resolver) {
		ldns_resolver_free(resolver);
		free(domainname); /* XXX is this ok for ldns? */
		resolver = NULL;
		domainname = NULL;
		action = "rereading";
	}

	status = ldns_resolver_new_frm_file(&resolver, resolv_conf);
	if (status != LDNS_STATUS_OK) {
		if (asprintf(&es, "bad resolv.conf file: %s", ldns_get_errorstr_by_id(status)) == -1)
			err(1, "setupresolver");
//		fatalx(es);
	}

	dn = ldns_resolver_domain(resolver);
	if (dn == NULL) {
		domainname = NULL;
		if (gethostname(buf, sizeof buf) == -1) {
			printf("getdomainname failed\n");
			domainname = NULL;
		} else {
			i = 0;
			while (buf[i] != '.' && i < strlen(buf) -1)
				i++;

			if (buf[i] == '.' && strlen(buf) > 1) {
				i++;
				if (asprintf(&domainname, "%s", &buf[i]) == -1)
					err(1, "setupresolver");
			}
		}
	} else {
		domainname = ldns_rdf2str(dn);
		i = strlen(domainname);
		if (i >= 1)
			i--;
		if (domainname[i] == '.')
			domainname[i] = '\0';
	}

	printf("%s %s, serving: %s\n", action, resolv_conf, domainname ? domainname : "no local domain set");
}

struct memcache *mc;
char *mc_instance = "127.0.0.1:11211";

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

	setupresolver();
	setupmemcache();

	while (1)
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

		printf("query for: %s\n", hostname);
		id = ldns_pkt_id(query_pkt);

		/*
		telnet 127.0.0.1 11211
		set test.hu 0 0 1 0
		9
		STORED
		get test.hu
		*/

		// XXX FNV1a32 hash for hostname?
		char *ret = mc_aget(mc, hostname, strlen(hostname));
		if (ret)
		{
			snprintf(buf, sizeof buf, "127.0.0.%s", ret);
			free(ret);

			spoofquery(hostname, &buf, query_rr, id);
		} else {
			forwardquery(hostname, query_rr, id);
		}

		free(hostname);
		ldns_pkt_free(query_pkt);

	}

	return 0;
}
