#include <xplip.h>
#include <time.h>

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#endif

#include <openssl/rand.h>
#include <openssl/rc4.h>
#include <openssl/err.h>

#include "recurseutil.h"

/*
    Helpers
    We cannot share some stuff defined in resolve.c
*/
static INLINE void QuerySetFlagsOpcode(uint16 *flags, uint16 opcode)
{
    *flags |= (opcode & QUERY_FLAGS_OPCODE_MASK) << QUERY_FLAGS_OPCODE_SHIFT;
}

static INLINE void QuerySetFlagsRcode(uint16 *flags, uint16 rcode)
{
    *flags |= (rcode & QUERY_FLAGS_RCODE_MASK) << QUERY_FLAGS_RCODE_SHIFT;
}

void QueryFillHeader(struct QueryHeader *h, uint16 id)
{
    /* id */
    h->id    = id;

    //h->flags = QUERY_FLAGS_RD;
    QuerySetFlagsOpcode(&h->flags, QUERY_FLAGS_OPCODE_STANDARD);
    QuerySetFlagsRcode(&h->flags, QUERY_FLAGS_RCODE_NOERROR);

    /*  */
    h->questionnum = 0;
    h->answernum   = 0;
    h->authnum     = 0;
    h->addonnum    = 0;
}

/*
   DNS protocol
*/
/* defines here */

int QueryFillName(char *query, char *name)
{
    char *start = name;
    char *label;
    int   len;

    while((label = strchr(query, '.')) != NULL)
    {
        *label++ = '\0';
        len = strlen(query);

        *name++ = len;
        strncpy(name, query, len);
        name += len;

        query = label;

        if (*query == '\0')
        {
            break;
        }
    }

    len = strlen(query);

    *name++ = len;
    strncpy(name, query, len);
    name += len;
    *name++ = '\0';

    return(name - start);
}

void *QueryFillQuestion(void *q, char *query, uint16 type, uint16 class)
{
    uint16 *p;
    int     len;

    len = QueryFillName(query, q);

    p = (uint16 *)((char *)q + len);

    *p++ = htons(type);
    *p++ = htons(class);

    return((void *)p);
}

void QueryHeaderConvert(struct QueryHeader *h)
{
    h->id           = htons(h->id);
    h->flags        = htons(h->flags);
    h->questionnum  = htons(h->questionnum);
    h->answernum    = htons(h->answernum);
    h->authnum      = htons(h->authnum);
    h->addonnum     = htons(h->addonnum);
}

void AnswerHeaderConvert(struct QueryHeader *h)
{
    h->id           = ntohs(h->id);
    h->flags        = ntohs(h->flags);
    h->questionnum  = ntohs(h->questionnum);
    h->answernum    = ntohs(h->answernum);
    h->authnum      = ntohs(h->authnum);
    h->addonnum     = ntohs(h->addonnum);
}

int QueryParseName(void *message, char *nptr, char *dst, int *off)
{
    unsigned char len;
    int           err, namelen;

    len     = 0;
    namelen = 0;
    *off    = 0;

    while((len = *nptr)) {
        if (len & 0xc0) {
            uint16 o      = ((uint16 *)nptr)[0];
            uint16 offset = ntohs(o) & ~0xc000;

            err = QueryParseName(message, (char *)message + offset, dst, off);

            *off     = namelen + 2;

            dst     += err;
            namelen += err;
            nptr    += 2;

            return(namelen);
        }else{
            nptr++;

            strncpy(dst, nptr, len);

            dst += len;
            *dst++ = '.';

            nptr += len;
            namelen += len + 1;
        }
    }

    *dst = '\0';
    namelen++;
    *off = namelen;

    return(namelen);
}

static int QueryParseRdataNS(void *message, void *rdata, uint16 rdlen, void *dst, int dsize)
{
    int offset;

    return(QueryParseName(message, rdata, dst, &offset));
}

static int QueryParseRdataA(void *message, void *rdata, uint16 rdlen, void *dst, int dsize)
{
    char addr[INET_ADDRSTRLEN + 1] = ":";

    if (rdlen != 4)
    {
        return(-EINVAL);
    }

    //inet_ntop(AF_INET, rdata, addr, sizeof(addr));
    XplIPAddrString(rdata, addr, sizeof(addr));

    return(strprintf(dst, dsize, NULL, "%s", addr));//inet_ntoa(*((struct in_addr *)rdata))));
}

static int QueryParseRdataAAAA(void *message, void *rdata, uint16 rdlen, void *dst, int dsize)
{
    char addr[INET6_ADDRSTRLEN + 1] = "::";

    /* Check rdlen */
    if (rdlen != 16) {
        return(-EINVAL);
    }
    //inet_ntop(AF_INET6, rdata, addr, sizeof(addr));
    XplIPAddrString(rdata, addr, sizeof(addr));

    return(strprintf(dst, dsize, NULL, "%s", addr));
}

static int QueryParseRdataSOA(void *message, void *rdata, uint16 rdlen, void *dst, int dsize)
{
    struct  DnsSOA soa = {{0}, {0}, 0, 0, 0, 0, 0};
    int     offset;

    /* MName */
    QueryParseName(message, rdata, (void *)&soa.mname, &offset);
    rdata = (char *)rdata + offset;

    /* RName */
    QueryParseName(message, rdata, (void *)&soa.rname, &offset);
    rdata = (char *)rdata + offset;

    /* Serial/Refresh/Retry/Expire/Min */
    soa.serial  = (ntohl(((uint32 *)rdata)[0]) & 0xffffffff);
    soa.refresh = (ntohl(((uint32 *)rdata)[1]) & 0x7fffffff);
    soa.retry   = (ntohl(((uint32 *)rdata)[2]) & 0x7fffffff);
    soa.expire  = (ntohl(((uint32 *)rdata)[3]) & 0x7fffffff);
    soa.min     = (ntohl(((uint32 *)rdata)[4]) & 0x7fffffff);

    /* Print */
    return(strprintf(dst, dsize, NULL, "%s %s %ld %ld %ld %ld %ld", soa.mname, soa.rname, (long) soa.serial, (long) soa.refresh, (long) soa.retry, (long) soa.expire, (long) soa.min));
}

static int QueryParseRdataTXT(void *message, void *rdata, uint16 rdlen, void *dst, int dsize)
{
    struct  DnsTXT txt = {0, {0}};
    int     len;

    len = (*(char *)rdata & 0xff);

    if (len && len < DNS_TXT_LEN)
    {
        rdata = (char *)rdata + 1;
        memcpy(txt.text, rdata, len);
        txt.len = len;
    }

    /* Print */
    len++;
    dsize = (dsize > len) ? len : dsize;
    return(strprintf(dst, dsize, NULL, "%s", txt.text));
}

static int QueryParseRdataMX(void *message, void *rdata, uint16 rdlen, void *dst, int dsize)
{
    struct  DnsMX mx = {0, {0}};
    int     offset;

    mx.preference = (ntohs(((uint16 *)rdata)[0]) & 0xffff);
    rdata = (char *)rdata + 2;

    QueryParseName(message, rdata, (void *)&mx.host, &offset);

    return(strprintf(dst, dsize, NULL, "%d %s", mx.preference, mx.host));
}

/*
   Parsers
*/
struct _dns_rdata_type dns_rdata_types[256]; 
#if 0
= {
    [DNS_TYPE_A]     = {"A",     QueryParseRdataA},
    [DNS_TYPE_NS]    = {"NS",    QueryParseRdataNS},
    [DNS_TYPE_CNAME] = {"CNAME", QueryParseRdataNS},
    [DNS_TYPE_SOA] =   {"SOA",   QueryParseRdataSOA},
    [DNS_TYPE_AAAA]  = {"AAAA",  QueryParseRdataAAAA},
    [DNS_TYPE_PTR]   = {"PTR",   QueryParseRdataNS},
    [DNS_TYPE_MX]    = {"MX",    QueryParseRdataMX},
    [DNS_TYPE_TXT]   = {"TXT",   QueryParseRdataTXT},
    [DNS_TYPE_SPF]   = {"SPF",   QueryParseRdataTXT},
};
#endif

void InitDnsRTypes()
{
	dns_rdata_types[DNS_TYPE_A].name = "A";
	dns_rdata_types[DNS_TYPE_A].parse = QueryParseRdataA;

	dns_rdata_types[DNS_TYPE_NS].name = "NS";
	dns_rdata_types[DNS_TYPE_NS].parse = QueryParseRdataNS;

	dns_rdata_types[DNS_TYPE_CNAME].name = "CNAME";
	dns_rdata_types[DNS_TYPE_CNAME].parse = QueryParseRdataNS;

	dns_rdata_types[DNS_TYPE_SOA].name = "SOA";
	dns_rdata_types[DNS_TYPE_SOA].parse = QueryParseRdataSOA;

	dns_rdata_types[DNS_TYPE_AAAA].name = "AAAA";
	dns_rdata_types[DNS_TYPE_AAAA].parse = QueryParseRdataAAAA;

	dns_rdata_types[DNS_TYPE_PTR].name = "PTR";
	dns_rdata_types[DNS_TYPE_PTR].parse = QueryParseRdataNS;

	dns_rdata_types[DNS_TYPE_MX].name = "MX";
	dns_rdata_types[DNS_TYPE_MX].parse = QueryParseRdataMX;

	dns_rdata_types[DNS_TYPE_TXT].name = "TXT";
	dns_rdata_types[DNS_TYPE_TXT].parse = QueryParseRdataTXT;

	dns_rdata_types[DNS_TYPE_SPF].name = "SPF";
	dns_rdata_types[DNS_TYPE_SPF].parse = QueryParseRdataTXT;
}

struct RR *QueryParseRR(void *message, void *data, unsigned int *off)
{
    struct RR *rr;
    uint16     rlen;
    int        name_len, offset, hisize = 10;
    char       name[QUERY_RR_NAME_MAX_SIZE];

    name_len = QueryParseName(message, data, name, &offset);
    data    = (char *)data + offset;

    rlen = ntohs(((uint16 *)data)[4]);

    rr = MemMalloc(sizeof(struct RR) + rlen + 1);

    if (!rr)
    {
        errno = ENOMEM;
        return(NULL);
    }

    /* Set values */
    rr->namelen = strprintf(rr->name, sizeof(rr->name), NULL, "%s", name);
    rr->type    = ntohs(((uint16 *)data)[0]);
    rr->class   = ntohs(((uint16 *)data)[1]);
    rr->ttl     = ntohl(((uint32 *)data)[1]);
    rr->rdlen   = rlen;

    memcpy(rr->rdata, (char *)data + hisize, rr->rdlen);

    if (dns_rdata_types[rr->type].parse)
    {
        char rdata[QUERY_RR_NAME_MAX_SIZE];

        dns_rdata_types[rr->type].parse(message, rr->rdata, rr->rdlen, rdata, sizeof(rdata));
    }

    *off = offset + rlen + hisize;

    return(rr);
}

unsigned int GrepRR(void *message, void *data, struct RR *rr)
{
    uint16     rlen;
    int        name_len, offset, hisize = 10;
    char       name[QUERY_RR_NAME_MAX_SIZE];

    name_len = QueryParseName(message, data, name, &offset);
    data    = (char *)data + offset;

    rlen = ntohs(((uint16 *)data)[4]);

    /* Set values */
    rr->namelen = strprintf(rr->name, sizeof(rr->name), NULL, "%s", name);
    rr->type    = ntohs(((uint16 *)data)[0]);
    rr->class   = ntohs(((uint16 *)data)[1]);
    rr->ttl     = ntohl(((uint32 *)data)[1]);
    rr->rdlen   = rlen;

    return(offset + hisize);
}

int QueryParseQuestion(void *message, void *data, char *name, uint16 *type, uint16 *class)
{
    int namelen, offset;

    namelen = QueryParseName(message, data, name, &offset);
    data    = (char *)data + offset;

    *type   = ntohs(((uint16 *)data)[0]);
    *class  = ntohs(((uint16 *)data)[1]);

    return(offset + 4);
}

int QueryParseAnswer(void *data)
{
    void                *rrh;
    struct QueryHeader *h = data;
    struct RR           *rr = NULL;
    int                  i;

    unsigned int         offset;
    char                 name[QUERY_RR_NAME_MAX_SIZE];
    uint16               type, class;

    AnswerHeaderConvert(h);

    rrh = (void *)(h + 1);

    for (i = 0; i < h->questionnum; ++i) {
        rrh = (char *)rrh + QueryParseQuestion(data, rrh, name, &type, &class);
    }

    for (i = 0; i < h->answernum + h->authnum + h->addonnum; ++i) {
        offset = 0;
        rr = QueryParseRR(data, rrh, &offset);
        if (!rr)
        {
            break;
        }

        MemFree(rr);
        rrh = (char *)rrh + offset;
    }

    if (!rr)
    {
        return(-EINVAL);
    }

    return(0);
}

#if 0
static int CmpRR(struct RR *rr1, struct RR *rr2, void *rdata1, void *rdata2)
{
    int cmp;

    if ( (cmp = rr1->type - rr2->type) || (cmp = rr1->class - rr2->class) || (cmp = rr1->rdlen - rr2->rdlen))
    {
        return(cmp);
    }

    return(memcmp(rdata1, rdata2, rr1->rdlen));
}
#endif

static int CopyRR(void *data, struct RR *rr, void *odata, void *ordata)
{
    uint16 *a;
    uint32 *ttl;
    int     size, off;
    char    buf[128];

    size = strlen(rr->name);
    if (size && rr->name[--size] == '.')
    {
        rr->name[size] = '\0';
    }
    size = QueryFillName(rr->name, (char *)data);
    data = (char *)data + size;

    a      = (uint16 *)data;
    a[0]   = htons(rr->type);
    a[1]   = htons(rr->class);
    ttl    = (uint32 *)&a[2];
    ttl[0] = htonl(rr->ttl);

    switch(rr->type)
    {
        case DNS_TYPE_A:
            off  = rr->rdlen;
            a[4] = htons(rr->rdlen);
            memcpy(&a[5], ordata, rr->rdlen);
            break;
        case DNS_TYPE_CNAME:
        case DNS_TYPE_NS:
            off = QueryParseName(odata, ordata, buf, &off);

            if (off && (buf[--off] == '.' || buf[--off] == '.'))
            {
                buf[off] = '\0';
            }
            off   = QueryFillName(buf, (char *)&a[5]);
            a[4]  = htons(off);

            break;
        default:
			/* Don't copy anything */
			return(0);
            break;
    }

    return(size + off + 10);
}

/*
   A Cname merge
*/
#define ReachPacketSize(s, e) (((char *)e - (char *)s) > UDP_AN_MAX_SIZE)
int MergePacket(void *answ1, void *answ2)
{
    struct QueryHeader *h0, *h1, *h2;
    char                buf0[UDP_AN_MAX_SIZE * 3], *data0, *data1, *data2;
    int                 i, j, s, num1, num2;
    void               *p0, *p1, *p2;
    struct RR           rr1, rr2;
    uint16              type, class, *num0 = NULL;
    char                name[QUERY_RR_NAME_MAX_SIZE];

    data0 = buf0;
    data1 = answ1;
    data2 = answ2;

    memcpy(data0, data1, sizeof(struct QueryHeader));
    h0 = (struct QueryHeader *)data0;
    p0 = (void *)(h0 + 1);

    h1 = (struct QueryHeader *)data1;
    p1 = (void *)(h1 + 1);

    h2 = (struct QueryHeader *)data2;
    p2 = (void *)(h2 + 1);

    /* Fill Question */
    for (i = 0; i < h1->questionnum; i++)
    {
        name[0] = '\0';
        p1 = (char *)p1 + QueryParseQuestion((void *)data1, p1, name, &type, &class);
        /* Copy */
        j = strlen(name);
        if (j && name[--j] == '.')
        {
            name[j] = '\0';
        }
        p0 = QueryFillQuestion((void *)p0, name, type, class);
    }
    /* skip for p2 */
    p2 = (char *)p2 + QueryParseQuestion((void *)data2, p2, name, &type, &class);

    /* Cmp And copy */
	h0->answernum = h0->authnum = h0->addonnum = 0;
    for (s = SECTION_AN; (SECTION_ALL & s); s <<= 1)
    {
        switch(s)
        {
            case SECTION_AN:
                num1 = h1->answernum;
                num2 = h2->answernum;

                num0 = &h0->answernum;
                break;
            case SECTION_NS:
                num1 = h1->authnum;
                num2 = h2->authnum;

                num0 = &h0->authnum;
                break;
            case SECTION_AR:
                num1 = h1->addonnum;
                num2 = h2->addonnum;

                num0 = &h0->addonnum;
                break;
            default:
                num1 = num2 = 0;
                break;
        }

		(*num0) = 0;

        for (i = 0; i < num1; i++)
        {
            p1 = (char *)p1 + GrepRR((void *)data1, p1, &rr1);

            /* Copy */
            j = CopyRR(p0, &rr1, data1, p1);
            p0 = (char *)p0 + j;

			if (ReachPacketSize(buf0, p0))
			{
				p0 = (char *)p0 - j;
				goto final;
			}
			if (j)
			{
				(*num0)++;
			}

            p1 = (char *)p1 + rr1.rdlen;
        }

        for (i = 0; i < num2; i++)
        {
            p2 = (char *)p2 + GrepRR((void *)data2, p2, &rr2);

#if 0
            /* Duplicate rr check */
            p = p00;
            for (j = 0; j < num1; j++)
            {
                p = (char *)p + GrepRR((void *)data0, p, &rr1);
                if (!CmpRR(&rr2, &rr1, p2, p))
                {
                    break;
                }
            }

            /* New */
            if (j == num1)
            {
                p0 = (char *)p0 + AddRR(p0, &rr2, p2);
                (*num0)++;
            }
#endif
            /* Copy */
            j = CopyRR(p0, &rr2, data2, p2);
            p0 = (char *)p0 + j;
			if (ReachPacketSize(buf0, p0))
			{
				p0 = (char *)p0 - j;
				goto final;
			}

			if (j)
			{
				(*num0)++;
			}

            p2 = (char *)p2 + rr2.rdlen;
        }
    }

final:
    /* Move back to answ1 */
    i = (char *)p0 - buf0;
    i = (i > UDP_AN_MAX_SIZE) ? UDP_AN_MAX_SIZE : i;

    memcpy(data1, buf0, i);

    return(i);
}

/*
   Pseudo random stuff
*/
#define SEED_SIZE   20
#define MAX_VALUE 0x7fffffff

static RC4_KEY rc4rndkey;

int InitArc4Random()
{
    time_t        seed = time(NULL);
    unsigned char rndbuf[SEED_SIZE];

    /* seed */
    if (!RAND_status())
    {
        unsigned char buf[256];
        size_t        i;
        time_t        v = seed;

        for (i = 0; i < 256/sizeof(time_t); i++)
        {
            memmove(buf + i * sizeof(time_t), &v, sizeof(time_t));
            v = v * seed + (time_t)i;
        }
        RAND_seed(buf, 256);
    }

    // Check Status ?

    /* Generate */
    memset(&rc4rndkey, 0, sizeof(RC4_KEY));
    memset(rndbuf, 0xc, sizeof(rndbuf));

    RAND_bytes(rndbuf, (int)sizeof(rndbuf));

    RC4_set_key(&rc4rndkey, SEED_SIZE, rndbuf);

    return(0);
}

int RndGenerate()
{
    unsigned int r = 0;

    RC4(&rc4rndkey, sizeof(r), (unsigned char *)&r, (unsigned char *)&r);

    return((int)(r % ((unsigned)MAX_VALUE + 1)));
}

/*
   Hash, support multiple data types
   http://burtleburtle.net/bob/hash/index.html
*/
#define ROT(x,k) (((x) << (k)) | ((x) >> (32 - (k))))
#define MIXHASH(a,b,c) \
{ \
  a -= c;  a ^= ROT(c, 4);   c += b; \
  b -= a;  b ^= ROT(a, 6);   a += c; \
  c -= b;  c ^= ROT(b, 8);   b += a; \
  a -= c;  a ^= ROT(c, 16);  c += b; \
  b -= a;  b ^= ROT(a, 19);  a += c; \
  c -= b;  c ^= ROT(b, 4);   b += a; \
}

#define FINALHASH(a,b,c) \
{ \
  c ^= b; c -= ROT(b, 14); \
  a ^= c; a -= ROT(c, 11); \
  b ^= a; b -= ROT(a, 25); \
  c ^= b; c -= ROT(b, 16); \
  a ^= c; a -= ROT(c, 4);  \
  b ^= a; b -= ROT(a, 14); \
  c ^= b; c -= ROT(b, 24); \
}

static uint32 HashData(const void *key, size_t length, uint32 initval)
{
    uint32 a,b,c;
    union { const void *ptr; size_t i; } u;

    /* Set up the internal state */
    a = b = c = 0xdeadbeef + ((uint32)length) + initval;

    u.ptr = key;
    if ((u.i & 0x3) == 0) {
        const uint32 *k = (const uint32 *)key;         /* read 32-bit chunks */

        while(length > 12)
        {
            a += k[0];
            b += k[1];
            c += k[2];

            MIXHASH(a,b,c);
            length -= 12;
            k += 3;
        }

        switch(length)
        {
            case 12: c += k[2]; b += k[1]; a += k[0]; break;
            case 11: c += k[2] & 0xffffff; b += k[1]; a += k[0]; break;
            case 10: c += k[2] & 0xffff; b += k[1]; a += k[0]; break;
            case 9 : c += k[2] & 0xff; b += k[1]; a += k[0]; break;
            case 8 : b += k[1]; a += k[0]; break;
            case 7 : b += k[1] & 0xffffff; a += k[0]; break;
            case 6 : b += k[1] & 0xffff; a += k[0]; break;
            case 5 : b += k[1] & 0xff; a += k[0]; break;
            case 4 : a += k[0]; break;
            case 3 : a += k[0] & 0xffffff; break;
            case 2 : a += k[0] & 0xffff; break;
            case 1 : a += k[0] & 0xff; break;
            case 0 : return(c);              /* zero length strings require no mixing */
      }

    } else if ((u.i & 0x1) == 0) {
        const uint16 *k = (const uint16 *)key;         /* read 16-bit chunks */
        const uint8  *k8;

        while (length > 12)
        {
            a += k[0] + (((uint32)k[1]) << 16);
            b += k[2] + (((uint32)k[3]) << 16);
            c += k[4] + (((uint32)k[5]) << 16);

            MIXHASH(a,b,c);
            length -= 12;
            k += 6;
        }

        k8 = (const uint8 *)k;
        switch(length)
        {
            case 12: c += k[4] + (((uint32)k[5]) << 16);
                 b += k[2] + (((uint32)k[3]) << 16);
                 a += k[0]+(((uint32)k[1]) << 16);
                 break;
            case 11: c += ((uint32)k8[10]) << 16;    /* fall through */
            case 10: c += k[4];
                b += k[2] + (((uint32)k[3]) << 16);
                a += k[0] + (((uint32)k[1]) << 16);
                break;
            case 9 : c += k8[8];                       /* fall through */
            case 8 : b += k[2] + (((uint32)k[3]) << 16);
                a += k[0] + (((uint32)k[1]) << 16);
                break;
            case 7 : b += ((uint32)k8[6]) << 16;     /* fall through */
            case 6 : b += k[2];
                a += k[0] + (((uint32)k[1]) << 16);
                break;
            case 5 : b += k8[4];                       /* fall through */
            case 4 : a += k[0] + (((uint32)k[1]) << 16);
                break;
            case 3 : a += ((uint32)k8[2]) << 16;     /* fall through */
            case 2 : a += k[0];
                break;
            case 1 : a += k8[0];
                break;
            case 0 : return(c);                       /* zero length requires no mixing */
        }
    } else {                        /*  read the key one byte */
        const uint8 *k = (const uint8 *)key;

        while (length > 12)
        {
            a += k[0];
            a += ((uint32)k[1]) << 8;
            a += ((uint32)k[2]) << 16;
            a += ((uint32)k[3]) << 24;
            b += k[4];
            b += ((uint32)k[5]) << 8;
            b += ((uint32)k[6]) << 16;
            b += ((uint32)k[7]) << 24;
            c += k[8];
            c += ((uint32)k[9]) << 8;
            c += ((uint32)k[10]) << 16;
            c += ((uint32)k[11]) << 24;
            MIXHASH(a,b,c);
            length -= 12;
            k += 12;
        }

        switch(length)                   /* all the case statements fall through */
        {
            case 12: c += ((uint32)k[11]) << 24;
            case 11: c += ((uint32)k[10]) << 16;
            case 10: c += ((uint32)k[9]) << 8;
            case 9 : c += k[8];
            case 8 : b += ((uint32)k[7]) << 24;
            case 7 : b += ((uint32)k[6]) << 16;
            case 6 : b += ((uint32)k[5]) << 8;
            case 5 : b += k[4];
            case 4 : a += ((uint32)k[3]) << 24;
            case 3 : a += ((uint32)k[2]) << 16;
            case 2 : a += ((uint32)k[1]) << 8;
            case 1 : a += k[0];
                break;
            case 0 : return(c);
        }
    }

    FINALHASH(a,b,c);

    return(c);
}

/*
   Hash table ops
*/
#define TABLESIZE    (1UL << 14)
#define TABLEMASK    TABLESIZE - 1

int
InitDnsCache(struct DnsCache *cache, size_t size, time_t ttl)
{
    size_t i;

    size = (size) ? size : TABLESIZE;

    cache->size  = size;
    cache->httl  = ttl; // Age

    cache->table = MemMalloc(size * sizeof(struct list));

    if (!cache->table)
    {
        return(-ENOMEM);
    }

    for (i = 0; i < size; i++)
    {
        LIST_INIT(&cache->table[i]);
    }

    LIST_INIT(&cache->queue);

    cache->total = 0;

    /* Lock */
    XplLockInit(&cache->lock);

    return(0);
}

void
DestroyDnsCache(struct DnsCache *cache)
{
    struct DnsItem  *rrs;
    struct list     *cur, *table;

    XplLockAcquire(&cache->lock);

	table = cache->table;
	cache->table = NULL;

	XplLockRelease(&cache->lock);

    while(!LIST_ISEMPTY(&cache->queue))
    {
        rrs = LIST_FIRST_ELEM(&cache->queue, struct DnsItem, rq);
        LIST_DEL(&rrs->rq, cur);

        DestroyDnsItem(rrs);
    }

    if (table)
    {
        MemFree(table);
    }
}

/* Quick helper */
/* Make sense to handle RAW qname with label and .  ? */
static uint32 MakeQueryHash(char *qname, uint16 type, uint16 class)
{
    uint32 h = 0xab;

#if defined(FULL_QUERY_HASH)
    h = HashData((void *)&type,  sizeof(type),  h);
    h = HashData((void *)&class, sizeof(class), h);
#endif
    /* FIXME: always lower case */
    h = HashData(qname, strlen(qname), h);

    return(h);
}

static INLINE void
MoveToFront(struct DnsCache *cache, struct list *hhead, struct DnsItem *item)
{
    struct list *pos;

    if (hhead->n != &item->list)
    {
        LIST_DEL(&item->list, pos);
        LIST_ADD(hhead, pos);
    }

    if (cache->queue.n != &item->rq)
    {
        LIST_DEL(&item->rq, pos);
        LIST_ADD(&cache->queue, pos);
    }
}

struct DnsItem *
GetDnsItem(struct DnsCache *cache, char *qname, uint16 type, uint16 class)
{
    struct list    *pos;
    struct DnsItem *item;
    uint32          h = (MakeQueryHash(qname, type, class) % cache->size);

	if (!cache->table)
	{
		return(NULL);
	}

    LIST_FOR_EACH(pos, &cache->table[h])
    {
        item = LIST_ELEM(pos, struct DnsItem, list);

        if (!stricmp(item->qname, qname) && item->type == type) // && item->class == class)
        {
            // Move to front
            MoveToFront(cache, &cache->table[h], item);

            return(item);
        }
    }

    return(NULL);
}

void
DeleteDnsItem(struct DnsCache *cache, struct DnsItem *item, int force)
{
    struct list *pos;

    if (!force && item->usecount > 0) return;

    reslog("Deleting Dns Item, zone: [%s]\n", item->qname);

    /* Unlink */
    LIST_DEL(&item->list, pos);
    LIST_DEL(&item->rq,   pos);

    DestroyDnsItem(item);
    cache->total--;
}

int
SetDnsItem(struct DnsCache *cache, char *qname, uint16 type, uint16 class, struct DnsItem **item)
{
	struct DnsItem	*temp;
    uint32          h = (MakeQueryHash(qname, type, class) % cache->size);

    /* Check again if it is in cache already */
    if (temp = GetDnsItem(cache, qname, type, class))
    {
        reslog("Dns Item already exists: [%s], type: [%d]\n", qname, type);
        DestroyDnsItem(*item);
		*item = temp;
        return(1);
    }

    /* Links */
    reslog("Dns Item Added: [%s], type: [%d]\n", qname, type);
    LIST_ADD(&cache->table[h], &(*item)->list);
    LIST_ADD(&cache->queue,    &(*item)->rq);
    cache->total++;

    /* Check size, we should make it retryable, Cache too big ? */
    if (cache->total > cache->size * 10)
    {
        struct list *tail;
        int          i = 0;

        do
        {
            tail = cache->queue.p;

            temp = LIST_ELEM(tail, struct DnsItem, rq);

			reslog("Delete Dns Item for reaching limit: [%d]\n", cache->total);
			DeleteDnsItem(cache, temp, 1);

			i++;

        } while (cache->total > cache->size * 10 && i < 3);
    }

    return(0);
}

/* When need to destroy completely */
void DestroyDnsItem(struct DnsItem *item)
{
    reslog("Release Dns Item, Zone: [%s], Nsrl flag: [%d], ref: [%d]\n", item->qname, item->nss.nsrlflag, item->usecount);
    switch(item->type)
    {
        case DNS_TYPE_NS:
        {
            int i;

            for (i = 0; i < item->nss.count; i++)
            {
                if (item->nss.nss[i].name)
                {
                    reslog("\tRelease DnsDomain, name: [%s], ttd: [%lu], addr: [%s]\n",
                        item->nss.nss[i].name, item->nss.nss[i].ttd, inet_ntoa(item->nss.nss[i].addr));

                    MemFree(item->nss.nss[i].name);
                }
            }
        } break;
        default:
            break;
    }

    MemFree(item);
}

/*
   Debug Print
*/
static char *opcodetostr(uint16 op)
{
    char *str;

    switch(op)
    {
        case QUERY_FLAGS_OPCODE_STANDARD:
            str = "QUERY";
            break;
        case QUERY_FLAGS_OPCODE_INVERS:
            str = "IQUERY";
            break;
        case QUERY_FLAGS_OPCODE_STATUS:
            str = "STATUS";
            break;
        default:
            str = "UNKNOWN OP";
            break;
    }

    return(str);
}

static char *rcodetostr(uint16 rcode)
{
    char *str;

    switch(rcode)
    {
        case QUERY_FLAGS_RCODE_NOERROR:
            str = "NOERROR";
            break;
        case QUERY_FLAGS_RCODE_FORMAT_ERROR:
            str = "FMTERROR";
            break;
        case QUERY_FLAGS_RCODE_FAIL:
            str = "SERVFAIL";
            break;
        case QUERY_FLAGS_RCODE_NAME_ERROR:
            str = "NXDOMAIN";
            break;
        case QUERY_FLAGS_RCODE_NOT_IMPL:
            str = "NOTIMP";
            break;
        case QUERY_FLAGS_RCODE_REFUSED:
            str = "REFUSED";
            break;
        default:
            str = "UNKNOWN RCODE";
            break;
    }

    return(str);
}

static char *typetostr(uint16 type)
{
    int i;

    for (i = 0; lengthof(dns_rdata_types); i++)
    {
        if (i == type)
        {
            return((char *)dns_rdata_types[i].name);
        }
    }

    return("");
}

static char *sectiontostr(int section)
{
    char *str;

    switch(section)
    {
        case SECTION_QD:
            str = "QUESTION";
            break;
        case SECTION_AN:
            str = "ANSWER";
            break;
        case SECTION_NS:
            str = "AUTHORITY";
            break;
        case SECTION_AR:
            str = "ADDITIONAL";
            break;
        default:
            str = "UNKNOWN SECTION";
            break;
    }

    return(str);
}

void DebugPacket(void *p, int answer, FILE *fp)
{
    struct QueryHeader *h;
    char                lp[UDP_AN_MAX_SIZE];
    uint16              opcode, rcode, type, class;
    int                 i, s, num;
    char                name[QUERY_RR_NAME_MAX_SIZE];
    void               *ptr;
    struct RR           rr;

    memcpy(lp, p, UDP_AN_MAX_SIZE);

    h = (struct QueryHeader *)lp;

    fputs("(Header)\n", fp);

    if (!answer)
    {
        AnswerHeaderConvert(h);
    }

    ptr = (void *)(h + 1);

    opcode = (h->flags >> QUERY_FLAGS_OPCODE_SHIFT) & QUERY_FLAGS_OPCODE_MASK;
    rcode  = (h->flags >> QUERY_FLAGS_RCODE_SHIFT) & QUERY_FLAGS_RCODE_MASK;

    fprintf(fp, "     id : (%04x)\n", h->id);
    fprintf(fp, "     qr : %s(%d)\n", (h->flags & QUERY_FLAGS_RESPONSE) ? "RESPONSE" : "QUERY", h->flags & QUERY_FLAGS_RESPONSE);
    fprintf(fp, " opcode : %s(%d)\n", opcodetostr(opcode), opcode);
    fprintf(fp, "     aa : %s(%d)\n", (h->flags & QUERY_FLAGS_AA)? "AUTHORITATIVE" : "NON-AUTHORITATIVE", h->flags & QUERY_FLAGS_AA);
    fprintf(fp, "     tc : %s(%d)\n", (h->flags & QUERY_FLAGS_TC)? "TRUNCATED" : "NOT-TRUNCATED", h->flags & QUERY_FLAGS_TC);
    fprintf(fp, "     rd : %s(%d)\n", (h->flags & QUERY_FLAGS_RD)? "RECURSION-DESIRED" : "RECURSION-NOT-DESIRED", h->flags & QUERY_FLAGS_RD);
    fprintf(fp, "     ra : %s(%d)\n", (h->flags & QUERY_FLAGS_RA)? "RECURSION-ALLOWED" : "RECURSION-NOT-ALLOWED", h->flags & QUERY_FLAGS_RA);
    fprintf(fp, "  rcode : %s(%d)\n", rcodetostr(rcode), rcode);

    /* Each rr in sections */
    /*  section QD */
    fprintf(fp, "\n [QUESTION:%d]\n", h->questionnum);
    for (i = 0; i < h->questionnum; i++)
    {
        ptr = (char *)ptr + QueryParseQuestion((void *)lp, ptr, name, &type, &class);
        fprintf(fp, "  %s %s(%d) %s(%d)\n", name, typetostr(type), type, (class == QUERY_CLASS_IN) ? "IN" : "ANY", class);
    }

    for (s = SECTION_AN; (SECTION_ALL & s); s <<= 1)
    {
        switch(s)
        {
            case SECTION_AN:
                num = h->answernum;
                break;
            case SECTION_NS:
                num = h->authnum;
                break;
            case SECTION_AR:
                num = h->addonnum;
                break;
            default:
                num = 0;
                break;
        }

        fprintf(fp, "\n [%s:%d]\n", sectiontostr(s), num);
        for (i = 0; i < num; i++)
        {
            ptr = (char *)ptr + GrepRR((void *)lp, ptr, &rr);
            // name type class ttl
            fprintf(fp, " %s %s %s %ld", rr.name, typetostr(rr.type), (class == QUERY_CLASS_IN) ? "IN" : "ANY", (long) rr.ttl);
            if (dns_rdata_types[rr.type].parse)
            {
                char rdata[QUERY_RR_NAME_MAX_SIZE * 2];

                dns_rdata_types[rr.type].parse((void *)lp, ptr, rr.rdlen, rdata, sizeof(rdata));

                fprintf(fp, " %s", rdata);
            }
            fprintf(fp, "\n");

            /* */
            ptr = (char *)ptr + rr.rdlen;
        }
    }
}
