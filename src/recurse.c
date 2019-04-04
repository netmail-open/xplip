#include <xplip.h>
#include <time.h>

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#endif

#include "recurseutil.h"

extern struct _dns_rdata_type dns_rdata_types[256];

struct HintsSoa
{
    unsigned char zone[QUERY_D_NAME_MAX_SIZE];
    size_t        count;

    struct {
        struct sockaddr sa;
    } addrs[NS_MAX_SIZE];

    struct HintsSoa *next;
};

//#define VRF_QNAME

struct DnsConn
{
    XplSocket udp, tcp;

    struct sockaddr         local, remote;
    uint16                  qid;

    uint16                  type;
    uint16                  class;

#if defined(VRF_QNAME)
    char                    qname[QUERY_D_NAME_MAX_SIZE]; // We could skip it
#endif

    char                   *ahost;

    int                     state;
    time_t                  start;
};

static struct _dns_recurser
{
    int						(*salookup)(const void *, int, const void *);

    time_t					nstimeout;
    time_t					timeout;
    time_t					extrattl;

    struct sockaddr_storage	iface; // Will Allow to set iface

    struct DnsCache			cache;
} recurser;

#define DNS_R_MAXDEPTH  8
enum dns_res_state
{
    DNS_RES_START,
    DNS_RES_SEARCH,

    DNS_RES_FOREACH_NS,
    DNS_RES_RESOLVE_NS_0,
    DNS_RES_RESOLVE_NS_1,

    DNS_RES_FOREACH_AN, // question
    DNS_RES_QUERY_AN,   // Answer

    // CNAME 0, 1
    DNS_RES_CNAME_0,
    DNS_RES_CNAME_1,

    DNS_RES_FINISH,
    DNS_RES_DONE
};

struct dns_resolver
{
    struct DnsConn conn;

    /* When starting */
    char   qname[QUERY_D_NAME_MAX_SIZE];
    uint16 type;
    uint16 class;

    time_t start;

    struct _resprocess
    {
        enum dns_res_state  state;
        unsigned            retries;

        char                query[QUERY_MAX_SIZE];
        int                 querylen;

        char                answer[UDP_AN_MAX_SIZE];
        int                 answerlen;
        struct QueryHeader *ah;
        char               *aptr;

        /*
           Best way just use one hints
           root hints and ns hints
        */
        struct HintsSoa    *localhints;
        struct DnsItem     *dnshints;
        int                 ins;

        uint16              qid;
        uint16              type;
        uint16              class;
#if defined(VRF_QNAME)
        char                qname[QUERY_D_NAME_MAX_SIZE];
#endif
    } resprocs[DNS_R_MAXDEPTH];

    unsigned rp;
};

/* Root hints head */
static struct HintsSoa *hintshead = NULL;
static int				loadcount = 0;

static void HintsClose()
{
    struct HintsSoa *soa, *next;

    for (soa = hintshead; soa; soa = next)
    {
        next = soa->next;

        MemFree(soa);
    }

    hintshead = NULL;
}

static int DefaultRootHintsOpen()
{
    static const struct {
        int  af;
        char addr[INET6_ADDRSTRLEN];
    } root_hints[] = {
        { AF_INET,  "198.41.0.4"        },      /* A.ROOT-SERVERS.NET. */
        { AF_INET6, "2001:503:ba3e::2:30"   },  /* A.ROOT-SERVERS.NET. */
        { AF_INET,  "192.228.79.201"    },      /* B.ROOT-SERVERS.NET. */
        { AF_INET,  "192.33.4.12"       },      /* C.ROOT-SERVERS.NET. */
        { AF_INET,  "128.8.10.90"       },      /* D.ROOT-SERVERS.NET. */
        { AF_INET,  "192.203.230.10"    },      /* E.ROOT-SERVERS.NET. */
        { AF_INET,  "192.5.5.241"       },      /* F.ROOT-SERVERS.NET. */
        { AF_INET6, "2001:500:2f::f"    },      /* F.ROOT-SERVERS.NET. */
        { AF_INET,  "192.112.36.4"      },      /* G.ROOT-SERVERS.NET. */
        { AF_INET,  "128.63.2.53"       },      /* H.ROOT-SERVERS.NET. */
        { AF_INET6, "2001:500:1::803f:235"  },  /* H.ROOT-SERVERS.NET. */
        { AF_INET,  "192.36.148.17"     },      /* I.ROOT-SERVERS.NET. */
        { AF_INET,  "192.58.128.30"     },      /* J.ROOT-SERVERS.NET. */
        { AF_INET6, "2001:503:c27::2:30"    },  /* J.ROOT-SERVERS.NET. */
        { AF_INET,  "193.0.14.129"      },      /* K.ROOT-SERVERS.NET. */
        { AF_INET6, "2001:7fd::1"           },
        { AF_INET,  "199.7.83.42"       },      /* L.ROOT-SERVERS.NET. */
        { AF_INET6, "2001:500:3::42"        },
        { AF_INET,  "202.12.27.33"      },      /* M.ROOT-SERVERS.NET. */
        { AF_INET6, "2001:dc3::35"          },
    };
    struct HintsSoa        *hints;
    struct sockaddr_in     *in;
    int                     i, j, o;
    socklen_t               len;

    /* FIXME: we should fetch by '.' first */
    hints = MemMalloc(sizeof(struct HintsSoa));
    if (!hints)
    {
        return((errno = ENOMEM));
    }

    hints->zone[0] = '.';
    hints->zone[1] = '\0';

    hints->count   = 0;

    for (i = 0, j = 0; i < lengthof(root_hints); i++)
    {
        /* Ignore INET6 for now */
        if (root_hints[i].af == AF_INET6)
        {
            continue;
        }

        o = j % lengthof(hints->addrs);

        /* Address and port */
        in = (struct sockaddr_in *)&hints->addrs[o].sa;

        in->sin_family = AF_INET;
        //inet_pton(root_hints[i].af, root_hints[i].addr, &in->sin_addr);
        XplStrToIPAddr((char *)root_hints[i].addr, (struct sockaddr *)in, &len);
        in->sin_port = htons(53);

        /* Insert into zone */
        j++;
        if (hints->count < lengthof(hints->addrs))
        {
            hints->count++;
        }
    }

    /* Link as head */
    hints->next = hintshead;
    hintshead   = hints;

    return(0);
}

/* Return an address */
static struct HintsSoa *
QueryHints(const char *zone)
{
    struct HintsSoa *soa;

    for (soa = hintshead; soa; soa = soa->next)
    {
        if (!stricmp(soa->zone, zone))
        {
            break;
        }
    }

    return(soa);
}

/* We don't check expiration here */
static INLINE int
CheckDnsNSFlag(struct DnsDomain *d, char **ns, struct in_addr *addr)
{
    return(-EINVAL);
}

/* FIXME: we should do kind of sorting here based by ttl, glue */
static int
GrepDnsNSAddr(struct DnsItem *item, struct sockaddr_in *inaddr, char *host, int *iter)
{
    int                 i = RndGenerate();
    struct _ns         *__ns;
    struct DnsDomain   *d = &item->nss;

    if (!d->count)
    {
         return(2);
    }

    i = (!*iter) ? i : *iter;
    i = i % d->count;

    reslog("NS iterator: [%d] - [%d] - [%d]\n", i, *iter, d->count);

    /* Random Get */
    __ns = &d->nss[i];

    if (__ns->ttd >= time(NULL) && __ns->addr.s_addr)
    {
        inaddr->sin_family      = AF_INET;
        inaddr->sin_addr.s_addr = __ns->addr.s_addr;
        inaddr->sin_port        = htons(53);

        strprintf(host, QUERY_D_NAME_MAX_SIZE, NULL, "%s", __ns->name);

        reslog("Picked ns randomly: [%s] - [%d]\n", __ns->name, i);

        *iter = ++i;

        /* Found */
        return(0);
    }

    /* We have to loop around to find one */
    for (i = 0; i < d->count; i++)
    {
        __ns = &d->nss[i];

        if (__ns->ttd >= time(NULL) && __ns->addr.s_addr)
        {
            inaddr->sin_family      = AF_INET;
            inaddr->sin_addr.s_addr = __ns->addr.s_addr;
            inaddr->sin_port        = htons(53);

            strprintf(host, QUERY_D_NAME_MAX_SIZE, NULL, "%s", __ns->name);

            reslog("Picked ns in loop: [%s]\n", __ns->name);

            *iter = ++i;

            /* Found */
            return(0);
        }
    }

    /* Glueless */
    inaddr->sin_addr.s_addr = 0;
    for (i = 0; i < d->count; i++)
    {
        __ns = &d->nss[i];

        if (__ns->ttd >= time(NULL))
        {
            inaddr->sin_family      = AF_INET;
            inaddr->sin_addr.s_addr = __ns->addr.s_addr;
            inaddr->sin_port        = htons(53);

            strprintf(host, QUERY_D_NAME_MAX_SIZE, NULL, "%s", __ns->name);

            reslog("Picked ns in glueless: [%s]\n", __ns->name);

            *iter = ++i;

            /* Found half */
            return(1);
        }
    }

	/* Expired */
	item->nss.nsrlflag |= NSRL_EXPIRED;
	if (item->usecount > 1)
	{
		for (i = 0; i < d->count; i++)
		{
			__ns = &d->nss[i];
            __ns->ttd += (recurser.extrattl * 10);
		}

		for (i = 0; i < d->count; i++)
		{
			__ns = &d->nss[i];

			inaddr->sin_family      = AF_INET;
			inaddr->sin_addr.s_addr = __ns->addr.s_addr;
			inaddr->sin_port        = htons(53);

			strprintf(host, QUERY_D_NAME_MAX_SIZE, NULL, "%s", __ns->name);

			reslog("Picked ns in extened glueless: [%s]\n", __ns->name);

			*iter = ++i;

			/* Found extened one */
			return(3);
		}
	}

    /* Must be an expired domain nss */
    return(-EINVAL);
}

static int
TestNSRL(struct DnsItem *item)
{
    char           *z = item->qname;
    char            h[QUERY_D_NAME_MAX_SIZE], *hp, *np;
    struct in_addr  in;
    int             d = 0, n;
    int             err = 0;

    while(*z)
    {
        if (*z++ == '.') ++d;
    }

    if (d < 2) return(0);

    /*
       Looks like we have to go through each full name, because the list is mixed with wildcard and full name
    */
    for (n = 0; n < item->nss.count; n++)
    {
        in.s_addr = item->nss.nss[n].addr.s_addr;
        hp = h;
        np = item->nss.nss[n].name;

        if (!np)
        {
            continue;
        }

        d = 0;
        do
        {
            if (*np == '.') d++;

            *hp++ = *np++;
        } while(!(*np == '.' && *(np + 1) == '\0'));
        *hp = '\0';

        err = recurser.salookup((void *)h, ++d, (void *)&in);
        if (err)
        {
            break;
        }
    }

    return(err);
}

/*
   Recurser start/shutdown
*/
EXPORT int
InitRecurser(int (*sacompar)(const void *, int, const void *))
{
	if (loadcount++) return(1);

    /* Pseudo */
    InitArc4Random();

    /* Root hints */
    DefaultRootHintsOpen();

    recurser.salookup = sacompar;

    recurser.nstimeout= 3;
    recurser.timeout  = 15;//30;

    recurser.extrattl = (2 * 24 * 60 * 60);

	/* Default iface */
	recurser.iface.ss_family = AF_INET;

	// Rdata Types
	InitDnsRTypes();

    /* Cache */
    return(InitDnsCache(&recurser.cache, 0, 300));
}

EXPORT int
InitRecurserEx(int (*sacompar)(const void *, int, const void *), time_t timeout, size_t cachesize)
{
	if (loadcount++) return(1);

    /* Pseudo */
    InitArc4Random();

    /* Root hints */
    DefaultRootHintsOpen();

    recurser.salookup = sacompar;

    recurser.nstimeout= 3;
    recurser.timeout  = (timeout) ? timeout : 15;

    recurser.extrattl = (2 * 24 * 60 * 60);

	/* Default iface */
	recurser.iface.ss_family = AF_INET;

    /* Cache */
    return(InitDnsCache(&recurser.cache, cachesize, 300));
}

EXPORT int
SetIface(const char *addr, unsigned short port)
{
	int af = (strchr(addr, ':')) ? AF_INET6 : AF_INET;
    socklen_t len;

	if (af == AF_INET)
	{
		//inet_pton(af, addr, &((struct sockaddr_in *)&recurser.iface)->sin_addr);
        XplStrToIPAddr((char *)addr,  (struct sockaddr *)&recurser.iface, &len);

		((struct sockaddr_in *)&recurser.iface)->sin_port = htons(port);
	}else {
		//inet_pton(af, addr, &((struct sockaddr_in6 *)&recurser.iface)->sin6_addr);
        XplStrToIPAddr((char *)addr,  (struct sockaddr *)&recurser.iface, &len);

		((struct sockaddr_in6 *)&recurser.iface)->sin6_port = htons(port);
	}

	recurser.iface.ss_family = af;

	return(0);
}

EXPORT void
DestroyRecurser()
{
	if (--loadcount) return;

    /* Destroy hints (local + customize) */
    HintsClose();

    /* Cache */
    DestroyDnsCache(&recurser.cache);
    //MemDumpPools(stderr);
}

/*
   Allow more hints added from settings, it always is inserted to top
   It could be another '.'
   All addresses are ip4 for now
*/
EXPORT int
AddHints(char *zone, char **ip4addrs, size_t na)
{
    int                 i, o;
    struct HintsSoa    *hints;
    struct sockaddr_in *in;
    char               *ip;
    socklen_t           len;

    if (!ip4addrs || !na) return(-1);

    hints = MemMalloc(sizeof(struct HintsSoa));
    if (!hints)
    {
        return((errno = ENOMEM));
    }

    strprintf(hints->zone, QUERY_D_NAME_MAX_SIZE, NULL, "%s", zone);
    hints->count = 0;

    for (i = 0; i < na; i++)
    {
        o  = i % na;
        ip = ip4addrs[i];

        in = (struct sockaddr_in *)&hints->addrs[o].sa;

        //inet_pton(AF_INET, ip, &in->sin_addr);
        XplStrToIPAddr(ip, (struct sockaddr *)in, &len);
        in->sin_port = htons(53);

        if (hints->count < na)
        {
            hints->count++;
        }
    }

    /* Insert to top */
    /* FIXME: lock here ? */
    hints->next = hintshead;
    hintshead   = hints;

    return(0);
}

static int
CreateQuery(void *qbuf, char *query, uint16 type, uint16 class, int proto, uint16 id)
{
    struct QueryHeader *h;
    void               *q;
    int                 querylen;

    h = (struct QueryHeader *)qbuf;

    /* By RFC, we might need to deal with TCP */
    if (proto == IPPROTO_TCP)
    {
        h = (struct QueryHeader *)((char *)qbuf + 2);
    }

    q = (void *)(h + 1);

    QueryFillHeader(h, id); // id is important in our case
    q = QueryFillQuestion(q, query, type, class);
    h->questionnum++;
    QueryHeaderConvert(h);

    querylen = (char * )q - (char *)qbuf;

    if (proto == IPPROTO_TCP)
    {
        uint16 *len = (uint16 *)qbuf;

        *len = ntohs(querylen);
        querylen += 2;
    }

    return(querylen);
}

/* so ops */
enum DnsConnState{
    DNS_CONN_INIT = 0,
    DNS_CONN_CONN,
    DNS_CONN_SEND,
    DNS_CONN_RECV,
    DNS_CONN_DONE,

    /* When tc is flagged */
    DNS_CONN_TCP_INIT,
    DNS_CONN_TCP_CONN,
    DNS_CONN_TCP_SEND,
    DNS_CONN_TCP_RECV,
    DNS_CONN_TCP_DONE,
};

/* Local conn ops */
static void CloseDnsConn (struct DnsConn *conn)
{
    //
    XplIpClose(conn->udp);
}

static int OpenDnsConn(struct DnsConn *conn, struct sockaddr *local, size_t addrlen, int type)
{
    /* By default, SOCK_DGRAM */
    conn->udp = XplIpSocket(local->sa_family, type, 0);
    if (!conn->udp) {
        return(-errno);
    }

    /* We go O_NONBLOCK */
    XplSocketSetMode(conn->udp, XPL_SOCKET_MODE_NON_BLOCKING);

    // local port should be 0

    /* Local one always AF(PF)_INET */
    if (XplIpBind(conn->udp, local, addrlen))
    {
        close(conn->udp);
        return(-errno);
    }

    return(0);
}

/* UDP poll for now */
#if defined(LINUX)
static int
DnsQueryPoll(struct DnsConn *conn, int timeout) //second
{
    struct pollfd pfd;
    int           err;

    pfd.fd      = conn->udp;
    switch(conn->state)
    {
        case DNS_CONN_RECV:
            pfd.events = POLLIN | POLLERR | POLLHUP;
            break;
        case DNS_CONN_CONN:
        case DNS_CONN_SEND:
            pfd.events = POLLOUT | POLLERR | POLLHUP;
            break;
        default:
            // error
            break;
    }

    err = poll(&pfd, 1, timeout);

    return(err);
}
#else
static int
DnsQueryPoll(struct DnsConn *conn, int timeout) //second
{
    int				ccode;
    fd_set			rfds;
	struct timeval	sTimeout;  /* select style timeout */

    FD_ZERO(&rfds);
    FD_SET(conn->udp, &rfds);

	sTimeout.tv_sec = timeout / 1000;
	sTimeout.tv_usec = ( timeout - sTimeout.tv_sec ) * 1000;

    ccode = XplIpSelect(0, &rfds, NULL, NULL, &sTimeout);
    if (ccode > 0) {
		errno = 0;
        return(ccode);
    }

    if (!ccode) {
        errno = ETIMEDOUT;
    }

    return SOCKET_ERROR;
}

#endif

static int
DnsConnStateCheck(struct DnsConn *conn, struct _resprocess *process)
{
    int             err = 0;
    ssize_t         n;
    uint16          type, class;

retry:
    switch(conn->state)
    {
        /* UDP */
        case DNS_CONN_INIT:
            conn->state++;
        case DNS_CONN_CONN:
            err = connect(conn->udp, (struct sockaddr *)&conn->remote, sizeof(struct sockaddr_in));

            if (err)
            {
                goto connerr;
            }

            conn->state++;
        case DNS_CONN_SEND:
            err = send(conn->udp, process->query, process->querylen, 0);

            if (err < 0)
            {
                goto connerr;
            }

            conn->state++;
        case DNS_CONN_RECV:
            /* sizeof(process->answer) */
            n = recv(conn->udp, (void *)process->answer, sizeof(process->answer), 0);

            if (n < 0)
            {
                goto connerr;
            }

            /* At least we should have header */
            if (n < 12)
            {
                goto retry;
            }

            /* We can verify now */
            process->answerlen = n;
            process->ah        = (struct QueryHeader *)process->answer;
            AnswerHeaderConvert(process->ah);

            /*
               Verify
            */
            reslog("Verifying received packet [%d-%d/%d]\n", process->ah->id, conn->qid, process->ah->questionnum);
            if (process->ah->id != conn->qid || !process->ah->questionnum)
            {
                goto retry;
            }
            process->aptr = (char *)(process->ah + 1);
            conn->ahost[0] = '\0';
            process->aptr += QueryParseQuestion(process->answer, process->aptr, conn->ahost, &type, &class);

#if defined(VRF_QNAME)
            reslog("Verifying, qname: [%s]", conn->qname);
#endif
            reslog("Verifying received packet [%s/%d-%d/%d-%d]\n", conn->ahost, type, conn->type, class, conn->class);

            if (conn->type != type || conn->class != class
#if defined(VRF_QNAME)
                || stricmp(conn->qname, conn->ahost)
#endif
               )
            {
                goto retry;
            }

            conn->state++;
        case DNS_CONN_DONE:
            /* Check header tc, see if we have to go to tcp */
            if (!(process->ah->flags & QUERY_FLAGS_TC))
            {
                return(0);
            }

            conn->state++;
        case DNS_CONN_TCP_INIT:
            // close current conn
            reslog("TCP Querying Required");
            goto connerr;

            // Reinit a tcp socket SOCK_STREAM
           conn->state++;
        default:
            err = EINVAL;
            break;
    }

connerr:
    switch(errno)
    {
        case EINTR:
            goto retry;
        case EINPROGRESS:
        case EALREADY:
        case EWOULDBLOCK:
            err = EAGAIN;
    }

    return(-err);
}

/*
   By RFC, it might need to use tcp (A different protocol)
*/
#if 0
/* tcp send/recv without polling */
static int DnsConnTcpSend(struct DnsConn *conn)
{
    return(0);
}

static int DnsConnTcpRecv(struct DnsConn *conn)
{
    return(0);
}
#endif

static INLINE struct DnsItem *CheckDnsItem(char *qname, int type)
{
	struct DnsItem *item = NULL;

    XplLockAcquire(&recurser.cache.lock);

    item = GetDnsItem(&recurser.cache, qname, DNS_TYPE_NS, QUERY_CLASS_IN);

    XplLockRelease(&recurser.cache.lock);

    return(item);
}

static struct DnsItem *
MakeNSHints(struct QueryHeader *h, void *pt, void *start, int full, int *new)
{
    int               i, c, l;
    char             *data = (char *)start;
    uint16            aun     = (h->authnum > NS_MAX_SIZE) ? NS_MAX_SIZE : h->authnum;
    uint16            aunfull = (full) ? aun + h->answernum : aun;
    struct DnsItem   *di;
    struct RR         *rr; //rr[aunfull];
	struct DnsItem	 *item;

    aun = aunfull;

	rr = MemMallocWait(sizeof(struct RR) * NS_MAX_SIZE);
    //memset(rr, 0, sizeof(rr));
    memset(rr, 0, sizeof(struct RR) * NS_MAX_SIZE);

    for (i = 0, c = 0; i < aun; i++)
    {
        data += GrepRR((void *)pt, data, &rr[i]);
		if( data > ((char *)start + sizeof(rr) ) )
		{
			break;
		}
        if (rr[i].type == DNS_TYPE_NS)
        {
            c++;
            rr[i].data = data;
        }

        data += rr[i].rdlen;
		if( data > ((char *)start + sizeof(rr) ) )
		{
			break;
		}
    }

    if (!c || !rr[0].name[0] || !rr[0].namelen)
    {
		MemFree(rr);
        return(NULL);
    }

    if (rr[0].name[0] && (item = CheckDnsItem(rr[0].name, DNS_TYPE_NS)))
    {
		MemFree(rr);
        return(item);
    }

    //l = rr[0].namelen + 1;
    //di = MemMalloc(sizeof(struct DnsItem) + c * sizeof(struct _ns) + l);
    di = MemMalloc(sizeof(struct DnsItem) + c * sizeof(struct _ns));
    if (!di)
    {
        reslog_err("Recurser : MakeNSHints : MemMalloc failed !");
		MemFree(rr);
        return(NULL);
    }
    //memset(di, 0, sizeof(struct DnsItem) + c * sizeof(struct _ns) + l);
    memset(di, 0, sizeof(struct DnsItem) + c * sizeof(struct _ns));

    di->type      = DNS_TYPE_NS;
    di->nss.count = c;

    //di->qname = (char *)(di->nss.nss + c);
    strprintf(di->qname, QUERY_RR_NAME_MAX_SIZE, NULL, "%s", rr[0].name);

    for (i = 0, c = 0; i < aun; i++)
    {
        if (rr[i].type == DNS_TYPE_NS && rr[i].data)
        {
            if(dns_rdata_types[rr[i].type].parse)
            {
                l = dns_rdata_types[rr[i].type].parse((void *)pt, rr[i].data, rr[i].rdlen, rr[i].name, sizeof(rr[i].name));

                if (!rr[i].name[0] || !l)
                {
                    continue;
                }

                di->nss.nss[c].name = MemMalloc(l + 1);

                if (di->nss.nss[c].name)
                {
                    strprintf(di->nss.nss[c].name, l + 1, NULL, "%s", rr[i].name);
                }
                else{
                    reslog_err("Recurser : MakeNSHints : MemMalloc name failed !");
                }
            }
            di->nss.nss[c].ttd = time(NULL) + rr[i].ttl + recurser.extrattl;
            c++;
        }
    }

    /* Get Addr in addon */
    for (i = 0; i < h->addonnum; i++)
    {
        data += GrepRR((void *)pt, data, &rr[0]);

        /* We only care IP4 */
        if (rr[0].type == DNS_TYPE_A && rr[0].rdlen == sizeof(struct in_addr))
        {
            for (c = 0; c < di->nss.count; c++)
            {
                if (di->nss.nss[c].name && !stricmp(di->nss.nss[c].name, rr[0].name))
                {
                    memcpy(&di->nss.nss[c].addr.s_addr, data, sizeof(struct in_addr));
                    break;
                }
            }
        }

        data += rr[0].rdlen;
    }

	*new = 1;
	MemFree(rr);
    return(di);
}

static void
UpdateNSHints(struct DnsItem *item, struct QueryHeader *h, void *pt, void *start, struct RR *anrr)
{
    int        i, j, s, num;
    char      *data = start;
    struct RR  rr, *rrp = NULL;
    time_t     nowstamp = time(NULL);

    for (s = SECTION_AN; (SECTION_ALL & s); s <<= 1)
    {
        switch(s)
        {
            case SECTION_AN:
                num = h->answernum;
                rrp = anrr;
                break;
            case SECTION_NS:
                /* Skip */
                for (i = 0; i < h->authnum; i++)
                {
                    data += GrepRR(pt, data, &rr);
                    data += rr.rdlen;
                }
                num = 0;
                break;
            case SECTION_AR:
                num = h->addonnum;
                rrp = &rr;
                break;
            default:
                num = 0;
                break;
        }

        /* addrs */
        for (i = 0; i < num; i++)
        {
            data += GrepRR(pt, data, rrp);

            if (rrp->type == DNS_TYPE_A && rrp->rdlen == sizeof(struct in_addr))
            {
                rrp->data = data;
                for (j = 0; j < item->nss.count; j++)
                {
                    /* Glue */
                    if (!stricmp(rrp->name, item->nss.nss[j].name) && !item->nss.nss[j].addr.s_addr)
                    {
                        memcpy(&item->nss.nss[j].addr.s_addr, data, sizeof(struct in_addr));
                        item->nss.nss[j].ttd = nowstamp + rrp->ttl + recurser.extrattl;

                        break;
                    }
                }
            }

            data += rrp->rdlen;
        }
    }
}

static INLINE void GetDnsItemRef(struct DnsItem *item)
{
    item->usecount++;
}
static INLINE void PutDnsItemRef(struct DnsItem *item)
{
    item->usecount--;
}
static INLINE void TimeOutPutDnsItemRef(struct dns_resolver *resolver)
{
    struct DnsItem *item = resolver->resprocs[0].dnshints;

    if (!item) return;

    XplLockAcquire(&recurser.cache.lock);

    item->nss.nsrlflag |= NSRL_TIMEOUT;
    reslog("Set Timeout Flag: [%s] - [%d]\n", item->qname, item->nss.nsrlflag);
    if (resolver->rp > 0 && resolver->resprocs[resolver->rp - 1].state == DNS_RES_RESOLVE_NS_1)
    {
        PutDnsItemRef(item);
    }

    XplLockRelease(&recurser.cache.lock);
}

/*
   RUn Query
*/
static int
RecurseQuery(struct dns_resolver *resolver)
{
    int                    err = 0, i;
    struct _resprocess    *process, *upprocess = NULL;
    struct sockaddr_in     sin;    // mostly sin
    char                   host[QUERY_D_NAME_MAX_SIZE];
    struct RR              rr;
    char                  *pocket = NULL, *data = NULL;
    uint16                 type = 0, class = 0;

    process = &resolver->resprocs[resolver->rp];

retry:
    switch(process->state){
        case DNS_RES_START:
            err = strprintf(host, QUERY_D_NAME_MAX_SIZE, NULL, "%s", resolver->qname);
            if (host[--err] == '.')
            {
                host[err] = '\0';
            }

            resolver->conn.qid   = MakeQID();
            resolver->conn.type  = resolver->type;
            resolver->conn.class = QUERY_CLASS_IN;

            /* use host for now */
            process->querylen = CreateQuery(process->query, host, resolver->type, resolver->class, IPPROTO_UDP, resolver->conn.qid);

            err = strprintf(host, QUERY_D_NAME_MAX_SIZE, NULL, "%s", resolver->qname);
#if defined(VRF_QNAME)
            strcpy(resolver->conn.qname, host);
#endif

            process->state++;
        case DNS_RES_SEARCH: // in hints and cache
        {
            char            *p;
            struct HintsSoa *hints;
            struct DnsItem  *dnshints;

            /* Found each domain for ns in cache */
            process->dnshints   = NULL;
            process->localhints = NULL;
            p = host;

            do {
                /* Search */
                XplLockAcquire(&recurser.cache.lock);
                dnshints = GetDnsItem(&recurser.cache, p, DNS_TYPE_NS, QUERY_CLASS_IN);
                process->ins = 0;
                if (dnshints)
                {
                    GetDnsItemRef(dnshints);
                    process->dnshints = dnshints;

                    reslog("Found NSS cache for zone: [%s]\n", dnshints->qname);

                    XplLockRelease(&recurser.cache.lock);
                    break;
                }
                XplLockRelease(&recurser.cache.lock);

                /* Hints */
                hints = QueryHints(p);
                if (hints)
                {
                    process->localhints = hints;
                    break;
                }

                /* Next zone */
                p = strchr(p, '.');
                if (p && *++p == '\0')
                {
                    --p;
                }
            } while (p);

            process->state++;
        }
        case DNS_RES_FOREACH_NS:
        {
            /* Select one ns to query with */
            /* Have to work with a ns set, when to release it if it in cache */
            /* Try to find the ns with address, if don't we go DNS_RES_FOREACH_AN anyway */
            if (process->localhints)
            {
                i = RndGenerate() % process->localhints->count;

                memcpy(&sin, &process->localhints->addrs[i], sizeof(struct sockaddr_in));

                strprintf(host, QUERY_D_NAME_MAX_SIZE, NULL, "%s", process->localhints->zone);
                process->state = DNS_RES_FOREACH_AN;
            }
            else if (process->dnshints)
			{
				/* Looping ? */
				if (++process->retries > 250)
				{
                    XplLockAcquire(&recurser.cache.lock);
                    PutDnsItemRef(process->dnshints);
                    XplLockRelease(&recurser.cache.lock);

                    err = QUERY_FLAGS_RCODE_NOT_IMPL;
                    goto quit;
				}

                /*
                   Test each NS
                */
                switch(GetNSRLFlag(process->dnshints) & (NSRL_CHECKED | NSRL_HOST_FLAG | NSRL_IP_FLAG))
                {
                    case NSRL_CHECKED:
                        break;
                    case NSRL_HOST_FLAG:
                    case NSRL_IP_FLAG:
                        XplLockAcquire(&recurser.cache.lock);
                        PutDnsItemRef(process->dnshints);
                        XplLockRelease(&recurser.cache.lock);

                        err = QUERY_FLAGS_RCODE_NAME_ERROR;
                        goto quit;
                    default:
                        if (recurser.salookup)
                        {
                            err = TestNSRL(process->dnshints);
                            if (err)
                            {
                                /* Set Flag */
                                XplLockAcquire(&recurser.cache.lock);

                                SetNSRLFlag(process->dnshints, NSRL_HOST_FLAG);
                                PutDnsItemRef(process->dnshints);

                                XplLockRelease(&recurser.cache.lock);

                                err = QUERY_FLAGS_RCODE_NAME_ERROR;

                                goto quit;
                            }

                            SetNSRLFlag(process->dnshints, NSRL_CHECKED);
                        }
                        break;
                }

                /* Continue */
                XplLockAcquire(&recurser.cache.lock);

                err = GrepDnsNSAddr(process->dnshints, &sin, host, &process->ins);
                switch(err)
                {
                    case 0:
                        PutDnsItemRef(process->dnshints);
                        process->state = DNS_RES_FOREACH_AN;
                        break;
					case 3:
                    case 1:
                        process->state++;
                        break;
                    case 2:
                    {
                        reslog_err("GrepDnsNSAddr result invalid");
                        err = QUERY_FLAGS_RCODE_NOT_IMPL;

                        PutDnsItemRef(process->dnshints);

                        XplLockRelease(&recurser.cache.lock);
                        goto quit;
                    } break;
                    default:
                        PutDnsItemRef(process->dnshints);

						if (process->dnshints->usecount > 0)
						{
							/* This would cause a loop */
                            err = QUERY_FLAGS_RCODE_NOT_IMPL;

                            XplLockRelease(&recurser.cache.lock);
                            goto quit;
						}
						else{
                            DeleteDnsItem(&recurser.cache, process->dnshints, 0);
                            process->state = DNS_RES_SEARCH;
						}

                        break;
                }

                XplLockRelease(&recurser.cache.lock);
            }
			else{
				reslog("Couldn't get localhints and hints, Retirs: [%d]", process->retries);
				err = QUERY_FLAGS_RCODE_NOT_IMPL;
				goto quit;
			}

            goto retry;
        } break;
        case DNS_RES_RESOLVE_NS_0:
        {
            char tmphost[QUERY_D_NAME_MAX_SIZE];

            reslog("Going to resolve NS for address : [%s]\n", host);

            if (resolver->rp + 1  >= DNS_R_MAXDEPTH)
            {
                err = QUERY_FLAGS_RCODE_TIMEOUT;
                goto quit;
            }

            /* Store old value */
            process->qid   = resolver->conn.qid;
            process->type  = resolver->conn.type;
            process->class = resolver->conn.class;
#if defined(VRF_QNAME)
            strprintf(process->qname, QUERY_D_NAME_MAX_SIZE, NULL, "%s", resolver->conn.qname);
#endif

            /* One More Deep */
            upprocess = &resolver->resprocs[++resolver->rp];

            /* FIXME: Seek cache first */

            /* Create Query */
            resolver->conn.qid   = MakeQID();
            resolver->conn.type  = DNS_TYPE_A;
            resolver->conn.class = QUERY_CLASS_IN;

            err = strprintf(tmphost, QUERY_D_NAME_MAX_SIZE, NULL, "%s", host);
            if (tmphost[--err] == '.')
            {
                tmphost[err] = '\0';
            }

            upprocess->querylen = CreateQuery(upprocess->query, tmphost, DNS_TYPE_A, QUERY_CLASS_IN, IPPROTO_UDP, resolver->conn.qid);

#if defined(VRF_QNAME)
            err = strprintf(upprocess->qname, QUERY_D_NAME_MAX_SIZE, NULL, "%s", host);
            strncpy(resolver->conn.qname, host, QUERY_D_NAME_MAX_SIZE);
#endif

            /* when back */
            process->state++;

            process        = upprocess;
            process->state = DNS_RES_SEARCH;

            goto retry;
        } break;
        case DNS_RES_RESOLVE_NS_1: // back from up
        {
            struct RR anrr;

            /* Update */
            anrr.rdlen = 0;
            anrr.data  = 0;
            XplLockAcquire(&recurser.cache.lock);

            UpdateNSHints(process->dnshints, upprocess->ah, upprocess->answer, upprocess->aptr, &anrr);
            PutDnsItemRef(process->dnshints);

            XplLockRelease(&recurser.cache.lock);

            reslog("Updating NSHints, name, :[%s]\n", anrr.name);

            /* FIXME: we need to find a better way to do this */
            if (!anrr.data || !anrr.rdlen)
            {
                err = QUERY_FLAGS_RCODE_NOT_IMPL;
                goto quit;
            }
            else
            {
                sin.sin_family      = AF_INET;
                memcpy(&sin.sin_addr.s_addr, anrr.data, sizeof(struct in_addr));
                sin.sin_port        = htons(53);
            }

            /* Not Found : goto err */

            /* Restore status */
            resolver->conn.qid   = process->qid;
            resolver->conn.type  = process->type;
            resolver->conn.class = process->class;

#if defined(VRF_QNAME)
            strncpy(resolver->conn.qname, process->qname, QUERY_D_NAME_MAX_SIZE);
#endif

            /* we have glue */
            process->state++;
        }
        case DNS_RES_FOREACH_AN:

            /* Submit */
            resolver->conn.state  = 0;

            /* We have to fix port in advance */
            memcpy(&resolver->conn.remote, &sin, sizeof(struct sockaddr_in));
            resolver->conn.start = time(NULL);
            resolver->conn.ahost = host;

            /*
               DEBUG QUERY
            */
#if defined(RES_QUERY_DEBUG_PACKET)
            do
            {
                char raddr[INET_ADDRSTRLEN + 1];

                //inet_ntop(AF_INET, (void *)&((struct sockaddr_in *)&resolver->conn.remote)->sin_addr, raddr, sizeof(raddr));
                XplIPAddrString(&((struct sockaddr_in *)&resolver->conn.remote, raddr, sizeof(raddr)));
                reslog_packet(process->query, 0, "\nQUERYING %s/%s, rp: %d\n", host, raddr, resolver->rp);
            }while(0);
#endif

            process->state++;
        case DNS_RES_QUERY_AN:
            /* Check with elapsed time */
            if (time(NULL) - resolver->conn.start > recurser.nstimeout)
            {
                if (process->dnshints)
                {
                    XplLockAcquire(&recurser.cache.lock);
                    GetDnsItemRef(process->dnshints);
                    XplLockRelease(&recurser.cache.lock);
                }
                reslog("Conn Timeout, try to use another address\n");
                process->state = DNS_RES_FOREACH_NS;
				process->retries++;
                goto retry;
            }

            /* connection state */
            err = DnsConnStateCheck(&resolver->conn, process);
            if (err)
            {
                goto quit;
            }

            /* if it is completed */
            if (resolver->conn.state != DNS_CONN_DONE && resolver->conn.state != DNS_CONN_TCP_DONE)
            {
                goto quit;
            }

            /*
               DEBUG ANSWER
            */
#if defined(RES_QUERY_DEBUG_PACKET)
            reslog_packet(process->answer, 1, "\nANSWER, rp: %d\n", resolver->rp);
#endif

            /* We have the answer with decoded header */
            pocket = process->answer;
            data   = process->aptr;
            type   = resolver->conn.type;
            class  = resolver->conn.class;

            /*
               Check AN section
            */
            /* IF found or CName */
            if (process->ah->answernum)
            {
                /* Foreach rr */
                for (i = 0; i < process->ah->answernum; i++)
                {
                    data += GrepRR((void *)pocket, data, &rr);

                    /* Do the check */
                    if (!stricmp(host, rr.name))
                    {
                        if(rr.type == type)
                        {
                            /* Found it */
                            process->state = DNS_RES_FINISH;
                            goto retry;
                        }
                        else if (rr.type == DNS_TYPE_CNAME) {
                            process->state = DNS_RES_CNAME_0;
                            goto retry;
                        }
						else{
							reslog("This type: [%d] is not expected in here !\n", rr.type);
							process->state = DNS_RES_FINISH;
							goto retry;
						}
                    }

                    data += rr.rdlen;
                }
            }

            /*
               Check NS Section
            */
            if (process->ah->authnum)
            {
				int new = 0;

                // Make DnsDomian
                process->dnshints   = MakeNSHints(process->ah, pocket, data, 0, &new);
                process->localhints = NULL;
                process->ins        = 0;

                if (process->dnshints)
                {
					if (new)
					{
						/* Insert into cache */
						XplLockAcquire(&recurser.cache.lock);

						SetDnsItem(&recurser.cache, process->dnshints->qname, DNS_TYPE_NS /*type*/, class, &process->dnshints);
						GetDnsItemRef(process->dnshints);

						XplLockRelease(&recurser.cache.lock);
					}
					else{
						XplLockAcquire(&recurser.cache.lock);
						GetDnsItemRef(process->dnshints);
						XplLockRelease(&recurser.cache.lock);
					}

                    process->state = DNS_RES_FOREACH_NS; // FIXME: right choice ?

                    goto retry;
                }
				/* Not able to get any hints, the packet could be bad one */
            }

            /*
               AA check
            */
            if (process->ah->flags & QUERY_FLAGS_AA)
            {
                process->state = DNS_RES_FINISH;
                goto retry;
            }

            /* FIXME: reasonable ? */
            process->state = DNS_RES_FOREACH_AN;
            goto retry;

        case DNS_RES_CNAME_0:
        {
            char tmphost[QUERY_D_NAME_MAX_SIZE];

            if (resolver->rp + 1  >= DNS_R_MAXDEPTH)
            {
                err = QUERY_FLAGS_RCODE_TIMEOUT;
                goto quit;
            }

            reslog("Checking CNAME type and parser, [%d]-[%p]\n", rr.type, dns_rdata_types[rr.type].parse);
            if (dns_rdata_types[rr.type].parse)
            {
                dns_rdata_types[rr.type].parse(pocket, data, rr.rdlen, host, sizeof(host));
            }

            reslog("Checking CNAME 0, [%s]\n", host);

            /* Keep state */
            process->qid   = resolver->conn.qid;
            process->type  = resolver->conn.type;
            process->class = resolver->conn.class;

#if defined(VRF_QNAME)
            strprintf(process->qname, QUERY_D_NAME_MAX_SIZE, NULL, "%s", resolver->conn.qname);
#endif

            /* One More Deep */
            upprocess = &resolver->resprocs[++resolver->rp];

            /* Search cache first */

            /* Build Query */
            resolver->conn.qid   = MakeQID();
            resolver->conn.type  = DNS_TYPE_A;
            resolver->conn.class = QUERY_CLASS_IN;

            err = strprintf(tmphost, QUERY_D_NAME_MAX_SIZE, NULL, "%s", host);
            if (tmphost[--err] == '.')
            {
                tmphost[err] = '\0';
            }

            upprocess->querylen = CreateQuery(upprocess->query, tmphost, DNS_TYPE_A, QUERY_CLASS_IN, IPPROTO_UDP, resolver->conn.qid);

#if defined(VRF_QNAME)
            err = strprintf(upprocess->qname, QUERY_D_NAME_MAX_SIZE, NULL, "%s", host);
            strncpy(resolver->conn.qname, host, QUERY_D_NAME_MAX_SIZE);
#endif

            /* when back */
            process->state++;

            process        = upprocess;
            process->state = DNS_RES_SEARCH;

            goto retry;
        }
        case DNS_RES_CNAME_1:
            /*
                Merge answers(process/upprocess)
            */
            //process->answerlen = MergePacket(process->answer, upprocess->answer);

            process->state = DNS_RES_DONE;
            goto retry;
        case DNS_RES_FINISH:
            if (resolver->rp > 0)
            {
                process->state++;
                goto retry;
            }

            /* Type check logic */
            switch(type)
            {
                case DNS_TYPE_A:
                case DNS_TYPE_NS:
                {
                    struct DnsItem *di;
					int             new = 0;

                    di = MakeNSHints(process->ah, pocket, process->aptr, 1, &new);
                    if (new && di)
                    {
                        /* Insert into cache */
                        XplLockAcquire(&recurser.cache.lock);

                        SetDnsItem(&recurser.cache, di->qname, DNS_TYPE_NS /*type*/, class, &di);

                        XplLockRelease(&recurser.cache.lock);
                    }

                } break;
                default: break;
            }

            break;
        case DNS_RES_DONE:
            /* sp > 0 pop */
            if (resolver->rp > 0)
            {
                upprocess = process;
                process   = &resolver->resprocs[--resolver->rp];

                goto retry;
            }

            break;
        default:
            break;
    }

quit:
    return(err);
}

static INLINE void MakeQname(char *qname, struct dns_resolver *resolver)
{
    char *p;

    strprintf(resolver->qname, sizeof(resolver->qname), NULL, "%s.", qname);

    /* Sanity for lookup */
    p = resolver->qname;
    while(*p)
    {
        if (*p >= 'A' && *p <= 'Z') {
            *p |= 0x20;
        }
        p++;
    }
}

static int QueryProcess(struct dns_resolver *resolver, int type)
{
    int err;

    /*
       Initialize resolver
    */
	/* Iface */
	memcpy(&resolver->conn.local, &recurser.iface, sizeof(resolver->conn.local));

    err = OpenDnsConn(&resolver->conn, &resolver->conn.local, sizeof(struct sockaddr_in), SOCK_DGRAM);
    if (err < 0)
    {
        reslog_err("OpenDnsConn failed");
        goto error;
    }

    resolver->type  = type;
    resolver->class = QUERY_CLASS_IN;

    resolver->start = time(NULL);

    /*
       State check recursively
    */
    while ((err = RecurseQuery(resolver)))
    {
        if (err != -EAGAIN)
        {
            // Log warnings
            goto error;
        }
        reslog("Got Connection EAGAIN Error, elapsed time: [%lu]\n", time(NULL) - resolver->start);

        /* If timeout */
        if (time(NULL) - resolver->start > recurser.timeout)
        {
            err = QUERY_FLAGS_RCODE_TIMEOUT;
            goto error;
        }

        /* Poll */
        DnsQueryPoll(&resolver->conn, 1000);
    }

error:
    CloseDnsConn(&resolver->conn);

    if (QUERY_FLAGS_RCODE_TIMEOUT == err)
    {
        TimeOutPutDnsItemRef(resolver);
    }

    return(err);
}

static INLINE int CheckNSRLFlag(struct dns_resolver *resolver)
{
    struct DnsItem     *d;
    unsigned            f = 0;

    XplLockAcquire(&recurser.cache.lock);

    d = GetDnsItem(&recurser.cache, resolver->qname, DNS_TYPE_NS, QUERY_CLASS_IN);
    if (d) {
        f = GetNSRLFlag(d);
    }
    XplLockRelease(&recurser.cache.lock);

    if (d)
    {
        if (f & (NSRL_HOST_FLAG | NSRL_IP_FLAG))
        {
            return(QUERY_FLAGS_RCODE_NAME_ERROR);
        }

        return(0);
    }

    return(-1);
}

/*
   Return a NXDOMAIN state if on the list
   0: ok
   NXDOMAIN: bad nsrl
   < 0, resolve sys err
   > 0,  resolve result err
*/
EXPORT int
DnsSAQuery(char *qname, int type)
{
    int                 err = QUERY_FLAGS_RCODE_NOERROR;
    struct dns_resolver resolver;

    if (type > DNS_TYPE_NS)
    {
        return(-(errno = EINVAL));
    }

    /* Query from Cache first */
    memset(&resolver, 0, sizeof(struct dns_resolver));
    MakeQname(qname, &resolver);

    /*
       First search in cache
    */
    err = CheckNSRLFlag(&resolver);
    if (err >= 0)
    {
        return(err);
    }

    /*
       Process
    */
    err = QueryProcess(&resolver, type);

    return(err);
}

/*
    Output: packetbuf
*/
EXPORT int
DnsRQueryPacket(char *qname, int type, char *packetbuf, int *size)
{
    int                 err = QUERY_FLAGS_RCODE_NOERROR;
    struct dns_resolver resolver;

    if (!packetbuf || !size || !*size) {
        return(-(errno = EINVAL));
    }

    /* Initialize */
    memset(&resolver, 0, sizeof(struct dns_resolver));
    MakeQname(qname, &resolver);

    /* NSRL Check */
    err = CheckNSRLFlag(&resolver);
    if (err > 0)
    {
        *size = 0;
        return(err);
    }

    /*
       Process
    */
    err = QueryProcess(&resolver, type);

    if (!err)
    {
        *size = (resolver.resprocs[0].answerlen > *size) ? *size : resolver.resprocs[0].answerlen;

        memcpy(packetbuf, resolver.resprocs[0].answer, *size);
    }
    else{
        *size = 0;
    }

    return(err);
}
