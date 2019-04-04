#ifndef _RECURSE_UTIL_H_INCLUDED_
#define _RECURSE_UTIL_H_INCLUDED_

#define QUERY_FLAGS_RESPONSE          0x8000      /* 0 - query, 1 - response */

#define QUERY_FLAGS_OPCODE_SHIFT        11
#define QUERY_FLAGS_OPCODE_MASK       0xf
#define QUERY_FLAGS_OPCODE_STANDARD     0         /* a standrad query: QUERY */
#define QUERY_FLAGS_OPCODE_INVERS       1         /* an inverse query: IQUERY */
#define QUERY_FLAGS_OPCODE_STATUS       2         /* a server status request: STATUS */
#define QUERY_FLAGS_OPCODE_NOTIFY       4
#define QUERY_FLAGS_OPCODE_UPDATE       5

#define QUERY_FLAGS_AA                  0x0400    /* authoritative answer */
#define QUERY_FLAGS_TC                  0x0200    /* truncation bit */
#define QUERY_FLAGS_RD                  0x0100    /* recursion desired */
#define QUERY_FLAGS_RA                  0x0080    /* recursion available */

#define QUERY_FLAGS_RCODE_SHIFT         0
#define QUERY_FLAGS_RCODE_MASK        0xf

#define QUERY_FLAGS_RCODE_NOERROR       0         /* no error response code */
#define QUERY_FLAGS_RCODE_FORMAT_ERROR  1         /* format error response code */
#define QUERY_FLAGS_RCODE_FAIL          2         /* server failure response code */
#define QUERY_FLAGS_RCODE_NAME_ERROR    3         /* name error response code */
#define QUERY_FLAGS_RCODE_NOT_IMPL      4         /* not implemented response code */
#define QUERY_FLAGS_RCODE_REFUSED       5         /* refused response code */

#define QUERY_FLAGS_RCODE_TIMEOUT       ETIMEDOUT /* Timeout */

struct QueryHeader
{
    uint16        id;
    uint16        flags;
    uint16        questionnum;
    uint16        answernum;
    uint16        authnum;
    uint16        addonnum;
};

#define QUERY_D_NAME_MAX_SIZE   256
#define QUERY_RR_NAME_MAX_SIZE  QUERY_D_NAME_MAX_SIZE

#define QUERY_MAX_SIZE          (12 + 256 + 4)
#define UDP_AN_MAX_SIZE         512

#define NS_MAX_SIZE             16

/*
   With extra info
*/
struct RR
{
    char          name[QUERY_RR_NAME_MAX_SIZE];
    int           namelen;//extra
    void         *data;   //extra

    uint16        type;
    uint16        class;
    uint32        ttl;
    uint16        rdlen;
    unsigned char rdata[];
};

enum query_class {
    QUERY_CLASS_IN = 1,     /* Internet */
    QUERY_CLASS_CS,         /* CSNET */
    QUERY_CLASS_CH,         /* CHAOS */
    QUERY_CLASS_HS,         /* Hesoid */
    QUERY_CLASS_ANY = 255,  /* any class */
};

enum rr_section
{
    SECTION_QD  = 0x01,      /* Question    */
    SECTION_AN  = 0x02,      /* Answer      */
    SECTION_NS  = 0x04,      /* Authority   */
    SECTION_AR  = 0x08,      /* Additional  */
    SECTION_ALL = 0x0f       /* All section */
};

#define DNS_TYPE_AAAA 28

/*
   We use defs in xplip.h,
   for the rest that we cannot share, we have to define them
*/
#if 0
enum query_type {
    QUERY_TYPE_A = 1,       /* a host address */
    QUERY_TYPE_NS,          /* an authoritative name server */
    QUERY_TYPE_MD,          /* a mail destination */
    QUERY_TYPE_MF,          /* a mail forwarder */
    QUERY_TYPE_CNAME,       /* the canonical name for the alias */
    QUERY_TYPE_SOA,         /* marks the start of a zone authority */
    QUERY_TYPE_MB,          /* a mailbox domain name */
    QUERY_TYPE_MG,          /* a mail group member */
    QUERY_TYPE_MR,          /* a mail rename domain name */
    QUERY_TYPE_NULL,        /* a null RR */
    QUERY_TYPE_WKS,         /* a well known service description */
    QUERY_TYPE_PTR,         /* a domain name pointer */
    QUERY_TYPE_HINFO,       /* host information */
    QUERY_TYPE_MINFO,       /* mailbox or mail list information */
    QUERY_TYPE_MX,          /* mail exchange */
    QUERY_TYPE_TXT,         /* text strings */
    QUERY_TYPE_AXFR = 252,  /* a request for a transfer of an entire zone */
    QUERY_TYPE_MAILB,       /* a request for mailbox-related records (MB, MG or MR) */
    QUERY_TYPE_ALL,         /* A request for all records */
};
#endif

/* DNS Query */
void       QueryHeaderConvert(struct QueryHeader *h);
void       AnswerHeaderConvert(struct QueryHeader *h);
int        QueryFillName(char *query, char *name);
void       QueryFillHeader(struct QueryHeader *h, uint16 id);
void      *QueryFillQuestion(void *q, char *query, uint16 type, uint16 class);
int        QueryParseName(void *message, char *nptr, char *dst, int *off);
struct RR *QueryParseRR(void *message, void *data, unsigned int *off);
unsigned int
           GrepRR(void *message, void *data, struct RR *rr);
int        QueryParseQuestion(void *message, void *data, char *name, uint16 *type, uint16 *class);
int        QueryParseAnswer(void *data);

int        MergePacket(void *answ1, void *answ2);

/* Pseudo */
#define MakeQID()  (((uint16)RndGenerate() >> 8) & 0xffff)
int        InitArc4Random(void);
int        RndGenerate(void);

/* list */
struct list {
    struct list *n;	/* next */
    struct list *p;	/* prev */
};
#define LIST_INIT(l)        ((l)->n = (l)->p = (l))
#define LIST_HEAD_INIT(l)   { &l, &l }
#define LIST_ADD(lh, el)    { (el)->n = (lh)->n; (el)->n->p = (lh)->n = (el); (el)->p = (lh); }
#define LIST_ADDQ(lh, el)   { (el)->p = (lh)->p; (el)->p->n = (lh)->p = (el); (el)->n = (lh); }
#define LIST_DEL(el, __ret) {(__ret) = (el); (el)->n->p = (el)->p; (el)->p->n = (el)->n;}
#define LIST_ELEM(lh, pt, el) (pt *) \
        ((unsigned char *)lh - offsetof(pt, el))
#define LIST_FIRST_ELEM(ptr, type, member) \
        LIST_ELEM((ptr)->n, type, member)
/* checks if the list head <lh> is empty or not */
#define LIST_ISEMPTY(lh)    ((lh)->n == (lh))
#define LIST_FOR_EACH(pos, head) \
        for (pos = (head)->n; pos != (head); pos = pos->n)

/* Hash table */
struct DnsCache{
    size_t       size;    //mask + 1
    size_t       httl;

    size_t       total;

    struct list *table;
    struct list  queue;

    XplLock      lock;
};

#define NSRL_NONE_FLAG  0x0
#define NSRL_HOST_FLAG  0x1
#define NSRL_IP_FLAG    0x2
#define NSRL_TIMEOUT    0x4
#define NSRL_CHECKED    0x8
#define NSRL_EXPIRED    0x10

struct _ns
{
	char           *name;   // Do we keep ns name here ?
	time_t          ttd;
	struct in_addr  addr;   // We want to save memory, only handle ip4 for now */
};

struct DnsDomain
{
    unsigned short	nsrlflag;    // Enable to trace ns name and addr
    unsigned short	count;

    /* Sortable */
    struct _ns   nss[0];
};

/* Ignore uint16 class for now */
struct DnsItem
{
    char        qname[QUERY_RR_NAME_MAX_SIZE];
    uint16      type;
    int         usecount; //atomic

    struct list list;
    struct list rq;

    struct  DnsDomain nss;

#if 0
    // NS/A/...
    union
    {
        struct dnsdomain nss;
        struct in_addr   addr;
    };
#endif
};

struct DnsSOA
{
    char     mname[QUERY_RR_NAME_MAX_SIZE];
    char     rname[QUERY_RR_NAME_MAX_SIZE];
    uint32   serial;
    uint32   refresh;
    uint32   retry;
    uint32   expire;
    uint32   min;
};

#define DNS_TXT_LEN 1024
struct DnsTXT
{
    size_t        len;
    unsigned char text[DNS_TXT_LEN];
};

struct DnsMX
{
    unsigned short preference;
    char           host[QUERY_RR_NAME_MAX_SIZE];
};

struct _dns_rdata_type {
    const char  *name;
    int        (*parse)(void *message, void *rdata, uint16 rdlen, void *dst, int dsize);
};

/* Hash */
int             InitDnsCache(struct DnsCache *cache, size_t size, time_t ttl);
void            DestroyDnsCache(struct DnsCache *cache);
struct DnsItem *GetDnsItem(struct DnsCache *cache, char *qname, uint16 type, uint16 class);
int             SetDnsItem(struct DnsCache *cache, char *qname, uint16 type, uint16 class, struct DnsItem **item);
/* FIXME: make it static */
void            DestroyDnsItem(struct DnsItem *item);
void            DeleteDnsItem(struct DnsCache *cahce, struct DnsItem *item, int force);

void			InitDnsRTypes(void);

/*
   Recurser
*/
#ifndef lengthof
#define lengthof(a) (sizeof (a) / sizeof (a)[0])
#endif

#define GetNSRLFlag(di)    ((di)->nss.nsrlflag)
#define SetNSRLFlag(di, f) ((di)->nss.nsrlflag |= (f))


/* Debug */
void DebugPacket(void *p, int in, FILE *fp);

#define resloga(f, ...) fprintf(stderr, f, ##__VA_ARGS__)
//#define reslog_err(f, ...) resloga(f ": %s [%d].\n", ##__VA_ARGS__, strerror(errno), errno)
#define reslog_err(f, ...) fprintf(stderr, f, ##__VA_ARGS__) 
#define reslog_packet(p, i, f, ...) \
    do {\
        resloga(f, ##__VA_ARGS__); \
        DebugPacket((p), (i), stderr);\
    } while(0)

//#define RES_QUERY_DEBUG
//#define RES_QUERY_DEBUG_PACKET

#ifdef RES_QUERY_DEBUG
#define reslog(f, ...) resloga(f, ##__VA_ARGS__)
#else
#define reslog(f, ...) do {} while (0)
#endif
#endif
