#include <xplip.h>
#include <errno.h>
#include <fcntl.h>
#include <xplthread.h>

/*
   Defs
*/
#define RADIX_NO_VALUE  0
#define RADIX_VALUE     1

typedef struct radix_node_s  radix_node_t;
struct radix_node_s {
    radix_node_t  *right;
    radix_node_t  *left;
    radix_node_t  *parent;
    unsigned       value:1;

    radix_node_t  *next;
};

typedef struct {
    radix_node_t  *root;
    radix_node_t  *free;

    size_t         size;
    radix_node_t  *head;
}radix_tree_t;

struct NSRLHostsSA
{
    char     **suffix;
    size_t     nsa;
    char      *buf;

    time_t     mtime;
};

struct NSRLCidrSA
{
    radix_tree_t *cidrtree;
    time_t        mtime;
};

struct cidr {
//    uint16          family;
    struct in_addr  addr;   // struct in6_addr
    struct in_addr  mask;   // struct in6_addr
};

/* Default SA files */
#define NSRL_HOSTS_SERVERAUTHORITY    XPL_BASE_DIR "/etc/nsrl.hosts.serverauthority"
#define NSRL_CIDR_SERVERAUTHORITY     XPL_BASE_DIR "/etc/nsrl.cidr.serverauthority"

/* Debug */
//#define NSRK_DEBUG

#ifdef NSRK_DEBUG
#define NSLog(f, ...) fprintf(stderr, f, ##__VA_ARGS__)
#else
#define NSLog(f, ...) do {} while(0)
#endif

#define NSErr(f, ...) fprintf(stderr, f ": [%d]\n", ##__VA_ARGS__, errno)


/* FIXME: Would be better if using some prealloc block */
static radix_node_t *
radix_alloc(radix_tree_t *tree)
{
    radix_node_t  *p;

    if (tree->free) {
        p = tree->free;
        tree->free = tree->free->right;
        return(p);
    }

    p = MemMalloc(sizeof(radix_node_t));
    memset(p, 0, sizeof(radix_node_t));
    tree->size++;

    p->next    = tree->head;
    tree->head = p;

    return(p);
}

static radix_tree_t *
radix_tree_create()
{
    radix_tree_t  *tree;

    tree = MemMalloc(sizeof(radix_tree_t));
    if (tree == NULL) {
        return NULL;
    }

    tree->free  = NULL;
    tree->size  = 0;
    tree->head  = 0;

    tree->root = radix_alloc(tree);
    if (!tree->root) {
        return(NULL);
    }

    tree->root->right  = NULL;
    tree->root->left   = NULL;
    tree->root->parent = NULL;
    tree->root->value  = RADIX_NO_VALUE;

//    tree->cap  = (1 << 13);

    return(tree);
}

static void radix_tree_destroy(radix_tree_t *tree)
{
    radix_node_t *node = tree->head, *next;

    while(node)
    {
        next = node->next;
        MemFree(node);
        node = next;
    }

    MemFree(tree);
}

static int
radix32tree_insert(radix_tree_t *tree, uint32 key, uint32 mask, unsigned value)
{
    uint32       bit;
    radix_node_t  *node, *next;

    bit = 0x80000000;

    node = tree->root;
    next = tree->root;

    while (bit & mask) {
        if (key & bit) {
            next = node->right;

        } else {
            next = node->left;
        }

        if (!next) {
            break;
        }

        bit >>= 1;
        node = next;
    }

    if (next) {
        if (node->value != RADIX_NO_VALUE) {
            return(-1);
        }

        node->value = value;
        return(0);
    }

    while (bit & mask) {
        next = radix_alloc(tree);
        if (next == NULL) {
            return(-1);
        }

        next->right = NULL;
        next->left = NULL;
        next->parent = node;
        next->value = RADIX_NO_VALUE;

        if (key & bit) {
            node->right = next;

        } else {
            node->left = next;
        }

        bit >>= 1;
        node = next;
    }

    node->value = value;

    return(0);
}

static unsigned
radix32tree_find(radix_tree_t *tree, uint32 key)
{
    uint32       bit;
    uintptr_t      value;
    radix_node_t  *node;

    bit   = 0x80000000;
    value = RADIX_NO_VALUE;
    node  = tree->root;

    while (node) {
        if (node->value != RADIX_NO_VALUE) {
            value = node->value;
        }

        if (key & bit) {
            node = node->right;

        } else {
            node = node->left;
        }

        bit >>= 1;
    }

    return(value);
}

/*
   Helper
*/
static int ptocidr(char *src, /* size_t len, */struct cidr *incidr)
{
    char   *addr, *mask/*, *last*/;
    uint32  s;
    socklen_t len;
    struct sockaddr_in sa;

    addr = src;

    mask = strchr(addr, '/');
    if (mask)
    {
        *mask++ = '\0';
    }

    //inet_pton(AF_INET, addr, &incidr->addr);
    XplStrToIPAddr(addr, (struct sockaddr *)&sa, &len);
    incidr->addr.s_addr = sa.sin_addr.s_addr;

    if (!mask)
    {
        incidr->mask.s_addr = 0xffffffff;
        return(0);
    }

    s = atoi(mask);

    if (s)
    {
        incidr->mask.s_addr = htonl((uint32) (0 - (1 << (32 - s))));
    }
    else{
        incidr->mask.s_addr = 0;
    }

    /* verify */

    return(0);
}

static int HostStrCmp(const void *a, const void *b)
{
    uintptr_t  c1, c2;
    char      *s1 = *(char **)a;
    char      *s2 = *(char **)b;

    for ( ;; ) {
        c1 = (uintptr_t) *s1++;
        c2 = (uintptr_t) *s2++;

        c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
        c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;

        if (c1 == c2) {

            if (c1) {
                continue;
            }

            return 0;
        }

        c1 = (c1 == '.') ? ' ' : c1;
        c2 = (c2 == '.') ? ' ' : c2;

        return(c1 - c2);
    }
}

/*
   Cidr list
*/
static void ReleaseCIDRSA(struct NSRLCidrSA *cidrsa)
{
    if (!cidrsa || !cidrsa->cidrtree) return;

    NSLog("CIDR Tree Nodes No [%zu]\n", cidrsa->cidrtree->size);

    radix_tree_destroy(cidrsa->cidrtree);
}

#if defined(LINUX)
#include <sys/mman.h>
static int LoadCIDRSA(char *cidrsafile, struct NSRLCidrSA *cidrsa)
{
    char        *p, *s, *e;
    int          fd;
    struct stat  st;
    char         cidrip4[32];
    struct cidr  incidr;

    if (!cidrsafile) {
        cidrsafile = NSRL_CIDR_SERVERAUTHORITY;
    }

    /* Open file */
    fd = open(cidrsafile, O_RDONLY);

    if (fd < 0) {
        return(-errno);
    }

    if (fstat(fd, &st) == -1) {
        return(-errno);
    }

    /*
       Compare mtime
    */
    if (st.st_mtime <= cidrsa->mtime)
    {
        close(fd);
        return(0);
    }

    /*
        Parse
    */
    p = (void *)mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        return(-errno);
    }

    s = p;

    /* Have tree ready */
    cidrsa->cidrtree = radix_tree_create();

    /* Build up cidr radix */
    do
    {
        e = cidrip4;

        while(*s && *s != '\r' && *s != '\n') {
           *e++ = *s++;
        }
        *e = '\0';

        /* Convert */
        ptocidr(cidrip4, &incidr);

        /* Insert */
        incidr.addr.s_addr = ntohl(incidr.addr.s_addr);
        incidr.mask.s_addr = ntohl(incidr.mask.s_addr);

//NSLog("Insert value : [%s]\n", cidrip4);

        radix32tree_insert(cidrsa->cidrtree, incidr.addr.s_addr, incidr.mask.s_addr, RADIX_VALUE);

        if (*s == '\r') s++;
        if (*s == '\n') s++;
    } while(s < p + st.st_size);

    /* Close */
    munmap(p, st.st_size);
    close(fd);

    /* keep mtime */
    cidrsa->mtime = st.st_mtime;

    return(0);
}

static int LoadHostsSA(char *hostssafile, struct NSRLHostsSA *hostssa)
{
    char        *p, *s, *d, *b, *e;
    int          fd;
    struct stat  st;
    size_t       n, l, i;
    char       **suffix;

    if (!hostssafile) {
        hostssafile = NSRL_HOSTS_SERVERAUTHORITY;
    }

    /* Open */
    fd = open(hostssafile, O_RDONLY);

    if (fd < 0) {
        return(-errno);
    }

    if (fstat(fd, &st) == -1) {
        return(-errno);
    }

    /*
       Compare mtime
    */
    if (st.st_mtime <= hostssa->mtime)
    {
        close(fd);
        return(0);
    }

    /*
       Parse
    */
    p = (void *)mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        return(-errno);
    }

    s = p;

    /* We don't want to load \r and first . */
    n = st.st_size;
    l = 0;
    do {
        if (*s == '\r') {
            --n;
        }

        if (*s == '\n') {
           l++;

           if (*(s + 1) == '.') {
               --n;
           }
        }

        s++;
    } while (s < p + st.st_size);

    b = MemMalloc(n * sizeof(char));
    if (!b)
    {
        return(-(errno = ENOMEM));
    }

    suffix = MemMalloc(l * sizeof(char *));
    if (!suffix)
    {
        return(-(errno = ENOMEM));
    }

    i = 0;
    e = b;
    s = p;

    do {
        if (*s == '.') {
            ++s;
        }

        d = s;

        suffix[i++] = e;
        while (*s && *s != '\r' && *s != '\n') {
            *e++ = *s++;
        }
        *e++ = '\0';

        if (*s == '\r')
        {
            ++s;
        }

        if (*s == '\n')
        {
            s++;
        }
    } while(s < p + st.st_size);

    /* Close */
    munmap(p, st.st_size);
    close(fd);

    /* Sort */
    qsort(suffix, l, sizeof(char *), HostStrCmp);

    /* b and suffix will be released later */
    hostssa->suffix = suffix;
    hostssa->nsa    = l;
    hostssa->buf    = b;
    hostssa->mtime  = st.st_mtime;

    return(0);
}
#else // windows

static int LoadCIDRSA(char *cidrsafile, struct NSRLCidrSA *cidrsa)
{
    char        *p, *s, *e;
    int          fd;
    struct stat  st;
    char         cidrip4[32];
    struct cidr  incidr;

    if (!cidrsafile) {
        cidrsafile = NSRL_CIDR_SERVERAUTHORITY;
    }

    /* Open file */
    fd = open(cidrsafile, O_RDONLY);

    if (fd < 0) {
        return(-errno);
    }

    if (fstat(fd, &st) == -1) {
        return(-errno);
    }

    /*
       Compare mtime
    */
    if (st.st_mtime <= cidrsa->mtime)
    {
        close(fd);
        return(0);
    }

    /*
        Parse
    */
	p = MemMallocWait(st.st_size);

	if (st.st_size != read(fd, p, st.st_size))
	{
		// error
	}

    s = p;

    /* Have tree ready */
    cidrsa->cidrtree = radix_tree_create();

    /* Build up cidr radix */
    do
    {
        e = cidrip4;

        while(*s && *s != '\r' && *s != '\n') {
           *e++ = *s++;
        }
        *e = '\0';

        /* Convert */
        ptocidr(cidrip4, &incidr);

        /* Insert */
        incidr.addr.s_addr = ntohl(incidr.addr.s_addr);
        incidr.mask.s_addr = ntohl(incidr.mask.s_addr);

//NSLog("Insert value : [%s]\n", cidrip4);

        radix32tree_insert(cidrsa->cidrtree, incidr.addr.s_addr, incidr.mask.s_addr, RADIX_VALUE);

        if (*s == '\r') s++;
        if (*s == '\n') s++;
    } while(s < p + st.st_size);

    /* Close */
	MemFree(p);

    close(fd);

    /* keep mtime */
    cidrsa->mtime = st.st_mtime;

    return(0);
}

static int LoadHostsSA(char *hostssafile, struct NSRLHostsSA *hostssa)
{
    char        *p, *s, *d, *b, *e;
    int          fd;
    struct stat  st;
    size_t       n, l, i;
    char       **suffix;

    if (!hostssafile) {
        hostssafile = NSRL_HOSTS_SERVERAUTHORITY;
    }

    /* Open */
    fd = open(hostssafile, O_RDONLY);

    if (fd < 0) {
        return(-errno);
    }

    if (fstat(fd, &st) == -1) {
        return(-errno);
    }

    /*
       Compare mtime
    */
    if (st.st_mtime <= hostssa->mtime)
    {
        close(fd);
        return(0);
    }

    /*
       Parse
    */
	p = MemMallocWait(st.st_size);

	if (st.st_size != read(fd, p, st.st_size))
	{
		// error
	}

    s = p;

    /* We don't want to load \r and first . */
    n = st.st_size;
    l = 0;
    do {
        if (*s == '\r') {
            --n;
        }

        if (*s == '\n') {
           l++;

           if (*(s + 1) == '.') {
               --n;
           }
        }

        s++;
    } while (s < p + st.st_size);

    b = MemMalloc(n * sizeof(char));
    if (!b)
    {
        return(-(errno = ENOMEM));
    }

    suffix = MemMalloc(l * sizeof(char *));
    if (!suffix)
    {
        return(-(errno = ENOMEM));
    }

    i = 0;
    e = b;
    s = p;

    do {
        if (*s == '.') {
            ++s;
        }

        d = s;

        suffix[i++] = e;
        while (*s && *s != '\r' && *s != '\n') {
            *e++ = *s++;
        }
        *e++ = '\0';

        if (*s == '\r')
        {
            ++s;
        }

        if (*s == '\n')
        {
            s++;
        }
    } while(s < p + st.st_size);

    /* Close */
	MemFree(p);
    close(fd);

    /* Sort */
    qsort(suffix, l, sizeof(char *), HostStrCmp);

    /* b and suffix will be released later */
    hostssa->suffix = suffix;
    hostssa->nsa    = l;
    hostssa->buf    = b;
    hostssa->mtime  = st.st_mtime;

    return(0);
}

#endif

/*
   Host List
*/
static void ReleaseHostsSA(struct NSRLHostsSA *hostssa)
{
    if (!hostssa || !hostssa->suffix || !hostssa->buf) {
       return;
    }

    MemFree(hostssa->buf);
    MemFree(hostssa->suffix);
}


/*
   Search
*/
static int FindCIDRSA(struct NSRLCidrSA *cidrsa, struct in_addr *in)
{
    unsigned long addr = in->s_addr;

    if (!cidrsa->cidrtree || !addr) return(0);

    addr = ntohl(addr);

    NSLog("FindCIDRSA, ip address: [%lu.%lu.%lu.%lu]\n",
        (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);

    if (radix32tree_find(cidrsa->cidrtree, addr))
    {
        NSLog("Found NSBL, ip address: [%lu.%lu.%lu.%lu]\n",
            (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);

        return(1);
    }

    return(0);
}

/* FIXME: host needs some normalize first ? */
static int FindHostsSA(struct NSRLHostsSA *hostssa, char *host, int nd)
{
    char *p;
    void *r;

    if (!hostssa->suffix) return(0);

    NSLog("FindHostsSA, Finding Host: [%s]/[%d]\n", host, nd);

    for (--nd, p = host; nd && p; p = strchr(p, '.'), ++p, --nd)
    {
//      NSLog("\tChecking SubDomain: [%s]\n", p);

        r = bsearch(&p, hostssa->suffix, hostssa->nsa, sizeof(char *), HostStrCmp);
        if (r)
        {
            NSLog("Found SA Host: [%s]\n", *(char **)r);
            return(1);
        }
    }

    return(0);
}

/*
   Interface
*/
static struct
{
    XplRWLock          lock;
    struct NSRLHostsSA hosts;
    struct NSRLCidrSA  cidrs;

    /* Update */
    char              *hostsafile;
    char              *cidrsafile;
    time_t             updateinterval;

    int                hasupdatethread;
} nsrlcheck;
static int nsrlupdatestop = 0;
static int loadcount = 0;

#define DEFAULT_UPDATE_INTERVAL  (60 * 60 * 2)

EXPORT int
LoadNSRL(char *hostsafile, char *cidrsafile)
{
	if (loadcount++) return(1);

    XplRWLockInit(&nsrlcheck.lock);
    memset(&nsrlcheck.hosts, 0, sizeof(struct NSRLHostsSA));
    nsrlcheck.cidrs.cidrtree = NULL;
    nsrlcheck.cidrs.mtime    = 0;

    nsrlcheck.updateinterval = DEFAULT_UPDATE_INTERVAL;
    nsrlcheck.hasupdatethread = 0;

    /* Load sas */
    nsrlcheck.hostsafile = hostsafile;
    LoadHostsSA(hostsafile, &nsrlcheck.hosts);
    if (!nsrlcheck.hosts.nsa)
    {
        NSErr("NSBL: Failed to load hosts server authority file: [%s]", NSRL_HOSTS_SERVERAUTHORITY);
		return(-(errno = EINVAL));
    }

    nsrlcheck.cidrsafile = cidrsafile;
    LoadCIDRSA(cidrsafile, &nsrlcheck.cidrs);
    if (!nsrlcheck.cidrs.cidrtree)
    {
        NSErr("NSBL: Failed to load cidr server authority file: [%s]", NSRL_CIDR_SERVERAUTHORITY);
		return(-(errno = EINVAL));
    }

    return(0);
}

EXPORT int
UnLoadNSRL()
{
	if (--loadcount) return(1);

    if (nsrlcheck.hasupdatethread)
    {
        nsrlupdatestop = 1;
        while(nsrlupdatestop)
        {
            XplDelay(1000);
        }
    }

    /* Unload sas */
    ReleaseHostsSA(&nsrlcheck.hosts);
    ReleaseCIDRSA(&nsrlcheck.cidrs);

    XplRWLockDestroy(&nsrlcheck.lock);

    return(0);
}

EXPORT int
SearchNSRL(const void *host, int nd, const void *ip4)
{
    int res = 0;

    /* ReadLock */
    XplRWReadLockAcquire(&nsrlcheck.lock);

    /* Host Or Ip */
    res = (FindHostsSA(&nsrlcheck.hosts, (char *)host, nd) || FindCIDRSA(&nsrlcheck.cidrs, (struct in_addr *)ip4));

    /* Unlock */
    XplRWReadLockRelease(&nsrlcheck.lock);

    NSLog("\tNsblSACmp, result: [%d], [%s]/[%lu]\n", res, (char *)host, (long)((struct in_addr *)ip4)->s_addr);

    return(res);
}

static int
UpdateNSRL()
{
    struct NSRLHostsSA hosts;
    struct NSRLCidrSA  cidrs;

    hosts.nsa      = 0;
    hosts.mtime    = nsrlcheck.hosts.mtime;
    cidrs.cidrtree = NULL;
    cidrs.mtime    = nsrlcheck.cidrs.mtime;

    /* Start to check */
    LoadHostsSA(nsrlcheck.hostsafile, &hosts);
    LoadCIDRSA(nsrlcheck.cidrsafile,  &cidrs);

    NSLog("NSBL Update Result, host nsa: [%d], cidr: [%p]\n",
            hosts.nsa, cidrs.cidrtree);

    if (hosts.nsa || cidrs.cidrtree)
    {
        /* Write Lock */
        XplRWWriteLockAcquire(&nsrlcheck.lock);

        if (hosts.nsa)
        {
            /* Destroy old one */
            ReleaseHostsSA(&nsrlcheck.hosts);

            /* Replace */
            nsrlcheck.hosts.suffix  = hosts.suffix;
            nsrlcheck.hosts.nsa     = hosts.nsa;
            nsrlcheck.hosts.buf     = hosts.buf;
            nsrlcheck.hosts.mtime   = hosts.mtime;
        }
        if (cidrs.cidrtree)
        {
            ReleaseCIDRSA(&nsrlcheck.cidrs);

            nsrlcheck.cidrs.cidrtree = cidrs.cidrtree;
            nsrlcheck.cidrs.mtime    = cidrs.mtime;
        }

        /* Unlock */
        XplRWWriteLockRelease(&nsrlcheck.lock);
    }

    return(0);
}

static int NsrlSAUpdate( XplThread_ thread )
{
    int                w;

    //while(nsrlupdatestop)
    for ( ;; )
    {
        /* Wait */
        for (w = 0; w < nsrlcheck.updateinterval && !nsrlupdatestop; w++)
        {
            XplDelay(1000);
        }
        if (nsrlupdatestop)
        {
            break;
        }

        /* Update */
        UpdateNSRL();
    }

    nsrlupdatestop = 0;
	return 0;
}

EXPORT int
StartNSRLUpdate(time_t interval)
{
    if (nsrlcheck.hasupdatethread) return(1);

    nsrlcheck.updateinterval = (interval) ? interval : nsrlcheck.updateinterval;

	XplThreadStart( NULL, NsrlSAUpdate, NULL, NULL );

    nsrlcheck.hasupdatethread = 1;

    return(0);
}
