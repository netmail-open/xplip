#include <xplip.h>
#include <time.h>

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#endif

#define RESOLVER_TIMEOUT	15
//#define DEBUG_SEARCH	1

#undef ns_c_in
# define ns_c_in 1

#define F_R_QR( f )	((f) >> 15 & 0x01)
#define F_R_OC( f )	((f) >> 11 & 0x0f)
#define F_R_AA( f )	((f) >> 10 & 0x01)
#define F_R_TC( f )	((f) >>  9 & 0x01)
#define F_R_RD( f )	((f) >>  8 & 0x01)
#define F_R_RA( f )	((f) >>  7 & 0x01)
#define F_R_Z( f )	((f) >>  4 & 0x03)
#define F_R_RC( f )	((f) >>  0 & 0x0f)

typedef struct
{
	uint16	id;
	uint16	flags;
	uint16	qdcount;
	uint16	ancount;
	uint16	nscount;
	uint16	arcount;
	unsigned char buffer[64 * 1024];
}RHeader Xpl8BitPackedStructure;

unsigned long DNSStartCount;
struct in_addr	DNSLocalAddr;

/* Query class constants */
#define CLASS_IN            0x0001    /* Internet class */

#define F_AUTHORITATIVE     0x0400    /* Response is authoritative                      */
#ifdef WIN32
/*******************************************************************************
******************************* WIN32 RESOLVER *********************************
*******************************************************************************/
#include<iphlpapi.h>
#define NO_LINUX_ONLY
#define NETDB_INTERNAL	-1
#define NETDB_SUCCESS	0

#define MAX_DNS_SERVERS	10
#define DNS_TIMEOUT		3000	// milliseconds

/* Constants for flags field of ResolveHeader */
#define F_TYPERESPONSE      0x8000    /* Packet contains response                       */
#define F_TYPEQUERY         0x0000    /* Packet contains query                          */

#define F_OPSTATUS          0x1000    /* Server status query                            */
#define F_OPINVERSE         0x0800    /* Inverse query                                  */
#define F_OPSTANDARD        0x0000    /* Standard query                                 */

#define F_AUTHORITATIVE     0x0400    /* Response is authoritative                      */
#define F_TRUNCATED         0x0200    /* Packet was truncated by network                */
#define F_WANTRECURSIVE     0x0100    /* Recursive lookup requested                     */
#define F_RECURSIVEUSED     0x0080    /* Recursive lookup available/used                */

#define F_RCMASK            0x000F    /* Throw away all but the return code             */
#define F_ERRREFUSED        0x0005    /* The request was refused                        */
#define F_ERRNOTIMP         0x0004    /* Query type isn't implemented by server         */
#define F_ERRNAME           0x0003    /* The name doesn't exist                         */
#define F_ERRFAILURE        0x0002    /* The name server experience an internal error   */
#define F_ERRFORMAT         0x0001    /* The server can't interpret the query           */
#define F_ERRNONE           0x0000    /* No errors occurred                             */


typedef struct
{
	uint16	type;
	uint16	class;
}QuestionInfo Xpl8BitPackedStructure;

typedef struct
{
	struct in_addr	addr;
}ServerAddress;

#endif

#define MAX_CACHE_HASH		1024
#define MAX_CACHE_ENTRIES	1024

// A AAAA Entry
typedef struct CacheEntry
{
	struct CacheEntry	*next;
	DNSQueryType		type;
	DNSLookupResult		result;
	XplAtomic			consumers;
	uint16				mx_prio;

	union
	{
		struct sockaddr_in		sin;
		struct sockaddr_in6		sin6;
	};

	time_t				addTime;
	char				name[];
}CacheEntry;

typedef struct
{
	XplLock lock;
	CacheEntry *list;
}CacheHashList;

typedef struct CacheAnswerEntry
{
	struct CacheAnswerEntry *next;
	DNSQueryType type;
	DNSLookupResult result;
	DNSAnswer *answer; // end with a char[]
	time_t addTime;
	XplAtomic consumers;
	char name[];
}CacheAnswerEntry;

typedef struct
{
	XplLock lock;
	CacheAnswerEntry *list;
}CacheAnswerHashList;

typedef struct
{
	XplAtomic cacheEntries;
	XplAtomic cached;
	XplAtomic resolved;
	XplAtomic lookup;
	CacheHashList cacheHash[MAX_CACHE_HASH];
	CacheAnswerHashList answerHash[MAX_CACHE_HASH];
	CacheHashList hosts;
	time_t hostTime;
	unsigned long timeout;
#ifdef WIN32
	ServerAddress DNSServer[MAX_DNS_SERVERS];
	int servers;
	XplAtomic requestNumber;
#endif

	/* Resolve Func */
	DNSLookupResult  (*resolve)(unsigned char *name, int rtype, RHeader *answer, int *size, unsigned char **bp);

	struct
	{
		int    recurserenabled;
		time_t rtimeout;
		size_t rcachesize;

		char   ifaceip[INET6_ADDRSTRLEN + 1];
		int    ifaceport;

		/* nameservers */
		char   nameservers[16][INET6_ADDRSTRLEN + 1];
	} config;
}DNSGlobals;

DNSGlobals DNS;

#ifdef WIN32
char *hostFile = "c:/windows/system32/drivers/etc/hosts";
#else
char *hostFile = "/etc/hosts";
#endif

#ifdef WIN32

int EncodeName( unsigned char *name, char **bp )
{
	char *p;
	unsigned char len;
	char *tmp;

	tmp = name = MemStrdupWait(name);

	for(p = strchr( name, '.' );p;p = strchr( name, '.' ) )
	{
		*p = '\0';
		len = strlen( name );
		*(*bp) = len;
		(*bp)++;
		strcpy( (*bp), name );
		(*bp) += len;
		*p = '.';
		p++;
		name = p;
	}
	len = strlen( name );
	*(*bp) = len;
	(*bp)++;
	strcpy( (*bp), name );
	(*bp) += len;
	// terminate
	*(*bp) = 0;
	(*bp)++;

	MemRelease(&tmp);

	return 0;
}

int res_query( unsigned char *host, int unused, int type, unsigned char *answer, int answerLen);
int res_init( void );

int res_query( unsigned char *host, int unused, int type, unsigned char *answer, int answerLen)
{
	int len, sock, l, bytes;
	unsigned char *p;
	RHeader question;
    struct sockaddr_in sin, from;

	memset( &question, 0, sizeof( RHeader ) );
	question.id = (uint16)XplSafeIncrement( DNS.requestNumber );
	question.flags = htons(F_TYPEQUERY | F_OPSTANDARD | F_WANTRECURSIVE);
	question.qdcount = htons(1);
	p = (unsigned char *)question.buffer;
	EncodeName( host, &p );
	((QuestionInfo *)p)->type = htons( (uint16)type );
	((QuestionInfo *)p)->class = htons( CLASS_IN );
	p += sizeof( QuestionInfo );
	len = p - (unsigned char *)&question;

	memset( &sin, 0, sizeof(struct sockaddr_in) );
	memset( &from, 0, sizeof(struct sockaddr_in) );
	sin.sin_family = AF_INET;
	from.sin_family = AF_INET;
	sin.sin_port = htons(53);
	from.sin_port = htons(0);

	for(l=0;l<DNS.servers;l++)
	{
		sin.sin_addr.s_addr = DNS.DNSServer[l].addr.s_addr;

		WSASetLastError( NETDB_INTERNAL );
		sock = XplIpSocket( PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if( !XplIpBind( sock, (struct sockaddr *)&from, sizeof( from ) ) )
		{
			if( len == XplIpSendTo( sock, (const char *)&question, len, 0, (struct sockaddr *)&sin, sizeof( sin ) ) )
			{
				bytes = XplIpRead((XplSocket)sock, answer, answerLen, DNS_TIMEOUT );
				XplIpClose( sock );
				if( bytes > 0 )
				{
					WSASetLastError( NETDB_SUCCESS );
					return bytes;
				}
			}
		}
		XplIpClose( sock );
	}
	return -1;
}

int res_init( void )
{
	IP_ADAPTER_INFO *info = NULL;
	IP_ADAPTER_INFO *adapter;
	IP_ADDR_STRING *server;
	IP_PER_ADAPTER_INFO *perInfo = NULL;
	ULONG len;
	DWORD error;
	struct in_addr addr;

	XplSafeInit( DNS.requestNumber, 0 );
	DNS.servers = 0;

	info = (IP_ADAPTER_INFO *)MemMalloc( sizeof(IP_ADAPTER_INFO) );
	len = sizeof( IP_ADAPTER_INFO );
	if( ERROR_BUFFER_OVERFLOW == (error = GetAdaptersInfo( info, &len ) ) )
	{
		MemFree( info );
		info = (IP_ADAPTER_INFO *)MemMalloc( len );
	}
	if( NO_ERROR == ( error = GetAdaptersInfo( info, &len ) ) )
	{
		perInfo = (IP_PER_ADAPTER_INFO *)MemMalloc( sizeof(IP_PER_ADAPTER_INFO) );
		len = sizeof( IP_PER_ADAPTER_INFO );

		for(adapter = info;adapter;adapter = adapter->Next)
		{
			if( ERROR_BUFFER_OVERFLOW == ( error = GetPerAdapterInfo( adapter->Index, perInfo, &len ) ) )
			{
				MemFree( perInfo );
				perInfo = (IP_PER_ADAPTER_INFO *)MemMalloc( len );
			}
			if( NO_ERROR == ( error = GetPerAdapterInfo( adapter->Index, perInfo, &len ) ) )
			{
				for(server=&perInfo->DnsServerList;server;server=server->Next)
				{
					addr.s_addr = inet_addr( server->IpAddress.String );
					if( addr.s_addr )
					{
						DNS.DNSServer[DNS.servers++].addr.s_addr = addr.s_addr;
					}
				}
			}
		}
	}

	if( info )
	{
		MemFree( info );
	}
	if( perInfo )
	{
		MemFree( perInfo );
	}
	return 0;
}

#endif

// bp pointer to buffer pointer
// op original buffer pointer or NULL if compression is disabled
// maxLen length of original buffer or of buffer if compression is disabled
// name output
static int DNSName( unsigned char **bp, unsigned char *op, int maxLen, unsigned char *name )
{
	// The XplBool, trailingDotNeedsToBeRemoved, was added as a safety
	// feature for the case of corrupt buffers.
	XplBool trailingDotNeedsToBeRemoved = FALSE;
	unsigned int len, off;
	unsigned char *minP, *maxP, *tmp;

	minP = op;
	maxP = op + maxLen - 1;

	if (NULL == *bp)
		return -1;

	do {
		if( *bp < minP || *bp > maxP )
		{
			//printf( "\n!!op: %s minP: %s maxP: %s\n", op, minP, maxP );
			//printf( "\n!!bp: %s\n", *bp );
			(*bp) = NULL;
			return -1;
		}

		len=*(*bp)++;
		if (!len){
			// This is one of two normal exits from the loop.
			break;
		}

		// check for compression
		if( op && ((len & 0xc0) == 0xc0 ))
		{
			off = (len & 0x3f) << 8;
			off += *(*bp)++;
			// process the pointer
			if( op + off > maxP )
			{
				*bp = NULL;
				return -1;
			}
			tmp = op + off;
			bp = &tmp;

			continue;
		}
		// fail if we try to look outside of the buffer
		if( (*bp) + len - 1 > maxP )
		{
			//printf( "\n!!op: %s minP: %s maxP: %s\n", op, minP, maxP );
			//printf( "\n!!bp+len: %s\n", *bp+len );
			*bp = NULL;
			return -1;
		}
		if( name )
		{
			memcpy( name, *bp, len );
			name += len;
			*name++ = '.';
			trailingDotNeedsToBeRemoved = TRUE;
		}
		(*bp) += len;
	} while (NULL != op);
	if( name && trailingDotNeedsToBeRemoved)
	{
		*(--name) = '\0';
	}

	return 0;
}

static int DNSText( unsigned char **bp, unsigned char *op, int size, unsigned char *text )
{
	unsigned int len;
	unsigned char *minP, *maxP;

	minP = op;
	maxP = op + size - 1;

	if( *bp < minP || *bp > maxP )
	{
		//printf( "\n!!op: %s minP: %s maxP: %s\n", op, minP, maxP );
		//printf( "\n!!bp: %s\n", *bp );
		(*bp) = NULL;
		return -1;
	}
	while( size )
	{
		len=*(*bp)++;
		size--;
		if( len )
		{
			if( *bp < minP || *bp > maxP )
			{
				//printf( "\n!!op: %s minP: %s maxP: %s\n", op, minP, maxP );
				//printf( "\n!!bp: %s\n", *bp );
				*bp = NULL;
				return -1;
			}
			// fail if we try to look outside of the buffer
			if( (*bp) + len - 1 > maxP )
			{
				//printf( "\n!!op: %s minP: %s maxP: %s\n", op, minP, maxP );
				//printf( "\n!!bp+len: %s\n", *bp+len );
				*bp = NULL;
				return -1;
			}
			if( text )
			{
				memcpy( text, *bp, len );
				text += len;
			}
			(*bp) += len;
			size -= len;
		}
	}
	if( text )
	{
		*text = '\0';
	}

	return 0;
}

static int DNSShort( unsigned char **bp, unsigned char *op, int opLen, uint16 *num )
{
	if( (*bp) && (*bp) + sizeof( uint16 ) <= op + opLen )
	{
		if( num )
		{
			*num = ntohs( *((uint16 *)(*bp)) );
		}
		(*bp) += sizeof( uint16 );
		return 0;
	}
	*bp = NULL;
	return -1;
}

static int DNSLong( unsigned char **bp, unsigned char *op, int opLen, uint32 *num )
{
	if( (*bp) && (*bp) + sizeof( uint32 ) <= op + opLen )
	{
		if( num )
		{
			*num = ntohl( *((uint32 *)(*bp)) );
		}
		(*bp) += sizeof( uint32 );
		return 0;
	}
	*bp = NULL;
	return -1;
}

static DNSQueryType DecodeAnswer( unsigned char **bp, unsigned char *op, size_t opLen, unsigned char *buffer, size_t bufferSize)
{
	DNSQueryType	outType;
	unsigned char	*tmp;
	uint32			ttl;
	uint16			type = 0, class = 0, rdl = 0;
	uint16			preference;

	outType = DNS_TYPE_NONE;

	DNSName( bp, op, opLen, buffer );
	DNSShort( bp, op, opLen, &type );
	DNSShort( bp, op, opLen, &class );
	DNSLong( bp, op, opLen, &ttl );
	DNSShort( bp, op, opLen, &rdl );
#if defined(DEBUG_SEARCH)
	printf( "Name:%s T:%d C:%d TTL:%lu RDL:%d\n", buffer, type, class, ttl, rdl );
#endif
	if( *bp && class == CLASS_IN )
	{
		// switch off to a temp so we dont modify the original pointer
		tmp = *bp;
		switch( type )
		{
			case DNS_TYPE_A:
				memcpy(buffer,tmp,sizeof(struct in_addr));
				outType = DNS_TYPE_A;
				break;
			case DNS_TYPE_AAAA:
				memcpy(buffer,tmp,sizeof(struct in6_addr));
				outType = DNS_TYPE_AAAA;
				break;

			case DNS_TYPE_PTR:
				if( !DNSName( &tmp, op, opLen, buffer ) )
				{
					outType = DNS_TYPE_PTR;
				}
				break;
			case DNS_TYPE_MX:
				if( !DNSShort( &tmp, *bp, rdl, &preference ))
				{
					if( !DNSName( &tmp, op , opLen, buffer ) )
					{
						strcatf( buffer, bufferSize, NULL, ":%d", preference );
						outType = DNS_TYPE_MX;
					}
				}
				break;
			case DNS_TYPE_TXT:
				if( !DNSText( &tmp, tmp, rdl, buffer ) )
				{
					outType = DNS_TYPE_TXT;
				}
				break;

			case DNS_TYPE_SOA:
				if( !DNSName( &tmp, op, opLen, buffer ) )
				{
					if( !DNSName( &tmp, op, opLen, buffer + strlen( buffer ) + 1 ) )
					{
						DNSLong( bp, op, opLen, &ttl );
						DNSLong( bp, op, opLen, &ttl );
						DNSLong( bp, op, opLen, &ttl );
						DNSLong( bp, op, opLen, &ttl );
						outType = DNS_TYPE_SOA;
					}
				}
				break;

			default:
				break;
		}
	}
	if( !bp )
	{
		return DNS_TYPE_NONE;
	}
	*bp += rdl;

	return outType;
}

#if defined(WIN32)
static int res_query_tcp(unsigned char *name, int rtype, RHeader *answer)
{
    return(-1);
}
#else
static int res_query_tcp(unsigned char *name, int rtype, RHeader *answer)
{
    struct __res_state _res_state;
    int r;

    memset(answer, 0, sizeof(RHeader));

    _res_state.options &= ~RES_INIT;
    res_ninit(&_res_state);

    _res_state.options |= RES_USEVC | RES_STAYOPEN | RES_USE_INET6;

    r = res_nquery(&_res_state, name, CLASS_IN, rtype, (unsigned char *)answer, sizeof( RHeader ));

    res_nclose(&_res_state);

    return(r);
}
#endif

static DNSLookupResult Resolve( unsigned char *name, int rtype, RHeader *answer, int *size, unsigned char **bp )
{
	int					l;
	DNSLookupResult 	result;

	memset( answer, 0, sizeof( RHeader ) );
	*size = res_query(name, CLASS_IN, rtype, (unsigned char *)answer, sizeof( RHeader ) );
    if (0 > *size && (answer->flags = ntohs( answer->flags )) && F_R_TC(answer->flags))
    {
#ifdef DEBUG_SEARCH
        fprintf(stderr, "RESOLVE: Truncated, retrying in TCP mode.\n");
#endif         
        *size = res_query_tcp(name, rtype, answer);
    }

	if( 0 > *size )
	{
#ifdef DEBUG_SEARCH
		XplConsolePrintf( "RESOLVE: %s failed to lookup with h_errno %d\n", name, h_errno );
#endif
		switch( h_errno )
		{
			case HOST_NOT_FOUND:	// authoritative
			case NO_DATA:			// zero records
				*size = 0;
				return DNS_AUTHORITATIVE_FAILURE;

			default:
			case NETDB_INTERNAL:	// internal error
			case TRY_AGAIN:			// non-authoritative host not found
			case NO_RECOVERY:		// FORMERR, REFUSED, NOTIMP
				*size = 0;
				return DNS_FAILURE;
		}
	}
#ifdef DEBUG_SEARCH
    printf( "Name: %s type:%d answer: %s size: %x\n", name, rtype,answer->buffer, *size );
#endif
	answer->id = ntohs( answer->id );
	answer->flags = ntohs( answer->flags );
	if( answer->flags & F_AUTHORITATIVE )
	{
		result = DNS_AUTHORITATIVE_SUCCESS;
	}
	else
	{
		result = DNS_SUCCESS;
	}
	answer->qdcount = ntohs( answer->qdcount );
	answer->ancount = ntohs( answer->ancount );
	answer->nscount = ntohs( answer->nscount );
	answer->arcount = ntohs( answer->arcount );

	if( !answer->ancount && !answer->nscount )
	{
#ifdef DEBUG_SEARCH
		XplConsolePrintf( "RESOLVE: %s has no answers\n", name );
#endif
		if( answer->flags & F_AUTHORITATIVE )
		{
			return DNS_AUTHORITATIVE_FAILURE;
		}
		return DNS_FAILURE;
	}

	// process questions
	*bp = answer->buffer;
	for(l=0;l<answer->qdcount;l++)
	{
		DNSName( bp, (unsigned char *)answer, *size, NULL );
		DNSShort( bp, (unsigned char *)answer, *size, NULL );
		DNSShort( bp, (unsigned char *)answer, *size, NULL );
	//	printf( "Name: %s T:%d C:%d\n", answer->, type, class );
	}

	if( *bp ){
		return result;
	}
#ifdef DEBUG_SEARCH
		XplConsolePrintf( "RESOLVE: %s failed to decode answer\n", name );
#endif
	*size=0; // todo : useless?
	return DNS_FAILURE;
}

static DNSLookupResult Lookup( const char *host, DNSQueryType type, DNSAnswer **answers )
{
	unsigned char	*bp;
	int				l;
	int				size;
	DNSAnswer		*an, **ap;
	RHeader			answer;
	DNSLookupResult	result;
	unsigned char	buffer[sizeof(RHeader)];

	*answers = NULL;
	if(  DNS_SUCCESS > ( result = DNS.resolve( (unsigned char *)host, type, &answer, &size,  &bp ) ) )
	{
		return result;	// failed
	}

	for(l=0;l<answer.ancount;l++)
	{
		if (type != DecodeAnswer( &bp, (unsigned char *)&answer, size, buffer, sizeof( buffer ))) {
			continue;
		}

		switch( type )
		{
			case DNS_TYPE_A:
				if( an = MemMallocEx( NULL, sizeof( DNSAnswer ) + sizeof( struct sockaddr_in ), NULL, FALSE, TRUE ) )
				{
					XplSafeInit( an->useCount, 1 );
					an->state = ANSWER_STATE_ACTIVE;
					an->type = DNS_ADDRESS;
					an->sa = (struct sockaddr *)&an->data;
					an->sin->sin_family = AF_INET;
					memcpy( &an->sin->sin_addr, buffer, sizeof( struct in_addr ) );
					an->next = *answers;
					*answers = an;
				}
				break;

			case DNS_TYPE_AAAA:
				if( an = MemMallocEx( NULL, sizeof( DNSAnswer ) + sizeof( struct sockaddr_in6 ), NULL, FALSE, TRUE ) )
				{
					XplSafeInit( an->useCount, 1 );
					an->state = ANSWER_STATE_ACTIVE;
					an->type = DNS_ADDRESS;
					an->sa = (struct sockaddr *)&an->data;
					an->sin6->sin6_family = AF_INET6;
					memcpy( &an->sin6->sin6_addr, buffer, sizeof( struct in6_addr ) );
					an->next = *answers;
					*answers = an;
				}
				break;

			case DNS_TYPE_MX:
				if( an = MemMallocEx( NULL, sizeof( DNSAnswer ) + strlen( buffer ) + 1, NULL, FALSE, TRUE ) )
				{
					char	*pref;

					XplSafeInit( an->useCount, 1 );
					an->state = ANSWER_STATE_ACTIVE;
					an->type = DNS_NAME;
					an->name = an->data;
					strcpy( an->name, buffer );
					if( pref = strchr( an->name, ':' ) )
					{
						*pref = '\0';
						an->mx_prio = atoi( pref+1 );
					}
					for(ap=answers;*ap;ap=&(*ap)->next)
					{

						if( an->mx_prio <= (*ap)->mx_prio)
						{
							an->next = *ap;
							*ap = an;
							break;
						}
					}
					if( !(*ap ) )
					{
						an->next = NULL;
						*ap = an;
					}
				}
				break;

			case DNS_TYPE_PTR:
			case DNS_TYPE_TXT:
				if( an = MemMallocEx( NULL, sizeof( DNSAnswer ) + strlen( buffer ) + 1, NULL, FALSE, TRUE ) )
				{
					XplSafeInit( an->useCount, 1 );
					an->state = ANSWER_STATE_ACTIVE;
					an->type = DNS_NAME;
					an->name = an->data;
					strcpy( an->name, buffer );
					an->next = *answers;
					*answers = an;
				}
				break;

			default:
				printf( " Unsuported DNSQueryType\n");
				break;
		}
	}
	if( !*answers )
	{
		return DNS_FAILURE;
	}
	return result;
}

static int HashName(const char *name )
{
	int hash;

	for(hash=0;*name;)
	{
		hash += *name & 0x07;
		name++;
		if( *name )
		{
			hash += (*name & 0x07) << 2;
			name++;
		}
		if( *name )
		{
			hash += (*name & 0x07) << 4;
			name++;
		}
		if( *name )
		{
			hash += (*name & 0x07) << 6;
			name++;
		}
	}
	return hash % MAX_CACHE_HASH;
}

static int HostEntry( char *line )
{
	struct addrinfo			hints, *info;
	char					*p, *address, *host;
	CacheEntry				*entry;
	struct sockaddr_storage	sa;

	if( ( p = strchr( line, '#' ) ) )
	{
		*p = '\0';
	}
	if( ( p = strchr( line, '\r' ) ) )
	{
		*p = '\0';
	}
	if( ( p = strchr( line, '\n' ) ) )
	{
		*p = '\0';
	}
	address = skipspace( line );
	if( *address )
	{
		if( host = strspace( address ) )
		{
			*host = '\0';
			while( host = skipspace( host+1 ) )
			{
				if( p = strspace( host ) )
				{
					*p = '\0';
				}
				info = NULL;
				memset( &sa, 0, sizeof( struct sockaddr_storage ) );
				memset( &hints, 0, sizeof( hints ) );
				hints.ai_family = PF_INET;
				hints.ai_protocol = SOCK_STREAM;
				getaddrinfo( line, NULL, &hints, &info );
				if( info )
				{
					if( ( entry = MemMalloc( sizeof( CacheEntry ) + strlen( host ) + 1 ) ) )
					{
						entry->type = DNS_TYPE_A;
						entry->result = DNS_AUTHORITATIVE_SUCCESS;
						memcpy( &entry->sin, info->ai_addr, info->ai_addrlen );
						entry->addTime = 0;	// not used
						XplSafeInit( entry->consumers, 0 );
						strcpy( entry->name, host );
						entry->next = DNS.hosts.list;
						DNS.hosts.list = entry;
					}
					freeaddrinfo( info );
				}
				else
				{
					hints.ai_family = PF_INET6;
					hints.ai_protocol = SOCK_STREAM;
					getaddrinfo( line, NULL, &hints, &info );
					if( info )
					{
						if( ( entry = MemMalloc( sizeof( CacheEntry ) + strlen( host ) + 1 ) ) )
						{
							entry->type = DNS_TYPE_AAAA;
							entry->result = DNS_AUTHORITATIVE_SUCCESS;
							memcpy( &entry->sin6, info->ai_addr, info->ai_addrlen );
							entry->addTime = 0;	// not used
							XplSafeInit( entry->consumers, 0 );
							strcpy( entry->name, host );
							entry->next = DNS.hosts.list;
							DNS.hosts.list = entry;
						}
						freeaddrinfo( info );
					}
				}
				if( p )
				{
					host = p;
				}
				else
				{
					break;
				}
			}
		}
	}
	return 0;
}

static DNSLookupResult FindHost( const char *name, DNSQueryType type, time_t now, DNSAnswer **answers )
{
	CacheEntry				*entry;
	DNSAnswer				*an;
	FILE					*fp;
	static time_t			lastCheck = 0;
	struct stat				st;
	char					lineBuff[1024];

	XplLockAcquire( &DNS.hosts.lock );
	if( now > lastCheck + 30 )
	{
		lastCheck = now;
		stat( hostFile, &st );
		if( st.st_mtime > DNS.hostTime )
		{
			DNS.hostTime = st.st_mtime;
			while( DNS.hosts.list )
			{
				entry = DNS.hosts.list->next;
				MemFree( DNS.hosts.list );
				DNS.hosts.list = entry;
			}
			if( ( fp = fopen( hostFile, "rb" ) ) )
			{
				while( !feof( fp ) )
				{
					if( !fgets( lineBuff, sizeof( lineBuff ), fp ) )
					{
						continue;
					}
					HostEntry( lineBuff );
				}
				fclose( fp );
			}
		}
	}
	for(entry=DNS.hosts.list;entry ;entry=entry->next)
	{
		if( type == entry->type )
		{
			if( !stricmp( name, entry->name ) )
			{
				switch( type )
				{
					case DNS_TYPE_A:
						if( an = MemMallocEx( NULL, sizeof( DNSAnswer ) + sizeof( struct sockaddr_in ), NULL, FALSE, TRUE ) )
						{
							XplSafeInit( an->useCount, 1 );
							an->state = ANSWER_STATE_ACTIVE;
							an->type = DNS_ADDRESS;
							an->sa = (struct sockaddr *)&an->data;
							an->sin->sin_family = AF_INET;
							memcpy( &an->sin->sin_addr, &entry->sin.sin_addr, sizeof( struct in_addr ) );
							an->next = *answers;
							*answers = an;

						}
						break;

					case DNS_TYPE_AAAA:
						if( an = MemMallocEx( NULL, sizeof( DNSAnswer ) + sizeof( struct sockaddr_in6 ), NULL, FALSE, TRUE ) )
						{
							XplSafeInit( an->useCount, 1 );
							an->state = ANSWER_STATE_ACTIVE;
							an->type = DNS_ADDRESS;
							an->sa = (struct sockaddr *)&an->data;
							an->sin6->sin6_family = AF_INET6;
							memcpy( &an->sin6->sin6_addr, &entry->sin6.sin6_addr, sizeof( struct in6_addr ) );
							an->next = *answers;
							*answers = an;
						}
						break;

					default:	// compiler warning
						break;
				}
				XplLockRelease( &DNS.hosts.lock );
				return DNS_AUTHORITATIVE_SUCCESS;
			}
		}
	}
	/*  We get here only if not found
	 */
	XplLockRelease( &DNS.hosts.lock );
	return DNS_FAILURE;
}

static DNSLookupResult NumericHost( const char *host, DNSQueryType type, DNSAnswer **answers )
{
	struct addrinfo	*info = NULL;
	DNSAnswer		*an;
	struct addrinfo	hints;

	if( !strcmp( host, "0.0.0.0" ) )
	{
		return DNS_AUTHORITATIVE_FAILURE;
	}
	memset( &hints, 0, sizeof( hints ) );
	hints.ai_flags = AI_NUMERICHOST;
	switch( type )
	{
		case DNS_TYPE_A:
			hints.ai_family = AF_INET;
			hints.ai_protocol = SOCK_STREAM;
			getaddrinfo( host, NULL, &hints, &info );
			if( info )
			{
				DebugAssert( sizeof( struct sockaddr_in ) == info->ai_addrlen );
				if( an = MemMallocEx( NULL, sizeof( DNSAnswer ) + sizeof( struct sockaddr_in ), NULL, FALSE, TRUE ) )
				{
					XplSafeInit( an->useCount, 1 );
					an->state = ANSWER_STATE_ACTIVE;
					an->type = DNS_ADDRESS;
					an->sa = (struct sockaddr *)&an->data;
					memcpy( an->sin, info->ai_addr, sizeof( struct sockaddr_in ) );
					an->next = *answers;
					*answers = an;

					freeaddrinfo( info );
					return DNS_AUTHORITATIVE_SUCCESS;
				}
				freeaddrinfo( info );
			}

			break;
		case DNS_TYPE_AAAA:
			hints.ai_family = AF_INET6;
			hints.ai_protocol = SOCK_STREAM;
			getaddrinfo( host, NULL, &hints, &info );
			if( info )
			{
				DebugAssert( sizeof( struct sockaddr_in6 ) == info->ai_addrlen );
				if( an = MemMallocEx( NULL, sizeof( DNSAnswer ) + sizeof( struct sockaddr_in6 ), NULL, FALSE, TRUE ) )
				{
					XplSafeInit( an->useCount, 1 );
					an->state = ANSWER_STATE_ACTIVE;
					an->type = DNS_ADDRESS;
					an->sa = (struct sockaddr *)&an->data;
					memcpy( an->sin6, info->ai_addr, sizeof( struct sockaddr_in6 ) );
					an->next = *answers;
					*answers = an;

					freeaddrinfo( info );
					return DNS_AUTHORITATIVE_SUCCESS;
				}
				freeaddrinfo( info );
			}

			break;
		default:	// fix compiler warning
			break;
	}
	return DNS_FAILURE;
}

static DNSLookupResult _GetAddrInfo( const char *host, DNSQueryType type, DNSAnswer **answers )
{
	struct addrinfo		hints, *info, *i;
	DNSAnswer			*an;
	size_t				length;

	memset(&hints, 0, sizeof (hints));
	hints.ai_family = ( DNS_TYPE_A == type ) ? AF_INET : AF_INET6;
	hints.ai_protocol = SOCK_STREAM;
	info = NULL;
	getaddrinfo(host, NULL, &hints, &info);
	if( info )
	{
		for(i=info;i;i=i->ai_next)
		{
			if( AF_INET == i->ai_family )
			{
				length = sizeof( struct sockaddr_in );
			}
			else if( AF_INET6 == i->ai_family )
			{
				length = sizeof( struct sockaddr_in6 );
			}
			else
			{
				continue;
			}
			an = MemMallocEx( NULL, sizeof( DNSAnswer ) + length, NULL, TRUE, TRUE );
			XplSafeInit( an->useCount, 1 );
			an->sa = (struct sockaddr *)&an->data;
			memcpy( an->sa, i->ai_addr, length );
			an->next = *answers;
			*answers = an;
		}
		freeaddrinfo( info );
	}
	return (*answers) ? DNS_SUCCESS : DNS_FAILURE;
}

static DNSLookupResult CacheAnswerFind( const char *name, struct DNSAnswer **answer, DNSQueryType type )
{
	int h, add;
	CacheAnswerEntry *del, *next, *entry, **ep;
	DNSAnswer *nextAnswer;
	time_t now;
	h = HashName( name );
	now = time(NULL);
	del = NULL;
	entry = NULL;

	add = 0;
	XplLockAcquire( &DNS.answerHash[h].lock );
	for(ep=&DNS.answerHash[h].list;*ep;ep=&(*ep)->next)
	{
		if( (*ep)->addTime && ( (*ep)->addTime + DNS.timeout < now ) )
		{
			// age the rest of the list
			del = *ep;
			*ep = NULL;
			break;
		}
		if( type == (*ep)->type && !stricmp( name, (*ep)->name ) )
		{
			XplSafeIncrement( (*ep)->consumers );
			break;
		}
	}
	entry = *ep;
#ifdef DEBUG_SEARCH
	if (entry) printf ("RESOLVE: Found in cache\n");
#endif
	if( !entry )
	{
		if( ( entry = MemMalloc( sizeof( CacheAnswerEntry ) + strlen( name ) + 1 ) ) )
		{
			XplSafeIncrement( DNS.cacheEntries );
			entry->type = type;
			entry->result=DNS_FAILURE; // unknown for now
			entry->answer = NULL;
			entry->addTime = 0;	// lookup in progress
			XplSafeInit( entry->consumers, 1 );
			strcpy( entry->name, name );
			entry->next = DNS.answerHash[h].list;
			DNS.answerHash[h].list = entry;
			add = 1;
		}
	}
	XplLockRelease( &DNS.answerHash[h].lock );

	while( del )
	{
		XplSafeDecrement( DNS.cacheEntries );
		next = del->next;
		while( XplSafeRead( del->consumers ) )
		{
			XplDelay( 20 );
		}
		while( del->answer )
		{
			nextAnswer = del->answer->next;
			if( del->answer )
			{
				del->answer->state = ANSWER_STATE_FREE;
				if( !XplSafeRead( del->answer->useCount ) )
				{
					MemFree( del->answer );
				}
			}
			del->answer = nextAnswer;
		}
		MemFree( del );
		del = next;
	}

	if( entry )
	{
		if( add )
		{
			if( ( DNS_TYPE_A == type ) || ( DNS_TYPE_AAAA == type ) )
			{
				entry->result = NumericHost( name, type, &entry->answer );
				if( DNS_FAILURE == entry->result )
				{
					entry->result = FindHost( name, type, now, &entry->answer );
					if( DNS_FAILURE == entry->result )
					{
						entry->result = _GetAddrInfo( name, type, &entry->answer );
					}
				}
			}
			if( DNS_FAILURE == entry->result )
			{
				entry->result = Lookup( name, type, &entry->answer);
				XplSafeIncrement( DNS.lookup );
			}
			entry->addTime = now;
		}
		else
		{
			while( !entry->addTime )
			{
				XplDelay( 20 );
			}
			nextAnswer = entry->answer;
			while( nextAnswer )
			{
				XplSafeIncrement( nextAnswer->useCount );
				nextAnswer = nextAnswer->next;
			}
			XplSafeIncrement( DNS.cached );
		}
		*answer = entry->answer;
		XplSafeDecrement( entry->consumers );
		return ( entry->result );

	}
	return DNS_FAILURE;
}

static void ClearCache( void )
{
	int h;
	CacheEntry *e, *en;
	CacheAnswerEntry *a, *an;
	DNSAnswer *aa;

	for(h=0;h<MAX_CACHE_HASH;h++)
	{
		XplLockAcquire( &DNS.hosts.lock );
		e = DNS.hosts.list;
		DNS.hosts.list = NULL;
		XplLockRelease( &DNS.hosts.lock );
		while( e )
		{
			en = e->next;
			MemFree( e );
			e = en;
		}
		XplLockAcquire( &DNS.cacheHash[h].lock );
		e = DNS.cacheHash[h].list;
		DNS.cacheHash[h].list = NULL;
		XplLockRelease( &DNS.cacheHash[h].lock );
		while( e )
		{
			en = e->next;
			MemFree( e );
			e = en;
		}
		XplLockAcquire( &DNS.answerHash[h].lock );
		a = DNS.answerHash[h].list;
		DNS.answerHash[h].list = NULL;
		XplLockRelease( &DNS.answerHash[h].lock );
		while( a )
		{
			an = a->next;
			while( a->answer )
			{
				aa = a->answer->next;
				if( XplSafeRead( a->answer->useCount ) )
				{
					XplConsolePrintf( "DNSCACHE: Releasing in use entry\r\n" );
				}
				MemFree( a->answer );
				a->answer = aa;
			}
			MemFree( a );
			a = an;
		}
	}
}

#if defined(NETWARE)
char *resolveConfigFile = "sys:/etc/resolve.cfg";
#elif defined(WIN32)
char resolveConfigFile[256];
#elif defined(SUSE) || defined(LINUX) || defined(S390RH) || defined(REDHAT) || defined(SOLARIS) || defined(MACOSX)
// TODO: is this suposed to be the system reslov file
// if yes the parser is broken
//char *resolveConfigFile = "/etc/resolv.confXXX";

/* It uses real system resolv.conf */
char *resolveConfigFile = "/etc/resolv.conf";
#endif

static void ReadResolverConfig( void )
{
	unsigned long lineNo;
	FILE *fp;
	char *p, *e;
	char line[256];
	int  nscount = 0;

#if defined(WIN32)
    GetWindowsDirectory(resolveConfigFile, sizeof( resolveConfigFile ) );
    strcat( resolveConfigFile, "\\resolve.cfg" );
#endif

	DNS.config.rtimeout   = 0;
	DNS.config.rcachesize  = 0;
	DNS.config.ifaceip[0] = '\0';
	DNS.config.ifaceport  = 0;
	DNS.config.recurserenabled = 0;

	if( (fp = fopen( resolveConfigFile, "rb" ) ) )
	{
		lineNo = 0;
		while( !feof( fp ) )
		{
			lineNo++;
			if( !fgets( line, sizeof( line ), fp ) )
			{
				continue;
			}
//			if( *line == ';' || ( *line == '/' && *(line+1) == '/' ) )
			if( *line == '#' || *line == ';' || ( *line == '/' && *(line+1) == '/' ) )
			{
				continue;
			}
			if( (p = strchr( line, '\r' ) ) )
			{
				*p = '\0';
			}
			if( (p = strchr( line, '\n' ) ) )
			{
				*p = '\0';
			}
			if( !*line )
			{
				continue;
			}

//			if( !(p = strchr( line, '=' ) ) )
			if( !(p = strchr( line, ' ' ) ) )
			{
				XplConsolePrintf( "RESOLVER: Syntax error on line %ld of %s\n", lineNo, resolveConfigFile );
				goto ConfigError;
			}
			e = p;
			while( e > line && isspace( *(e-1) ) )
			{
				e--;
				*e = '\0';
			}
			*p = '\0';
			p++;
			while( *p && isspace( *p ) )
			{
				p++;
			}

			if( !stricmp( line, "timeout" ) )
			{
				if( !( DNS.timeout = strtoul( p, NULL, 0 ) ) )
				{
					DNS.timeout = RESOLVER_TIMEOUT;
				}
#ifdef DEBUG_SEARCH
				XplConsolePrintf( "RESOLVER: Timeout set to %lu seconds\n", DNS.timeout );
#endif
			}
			else if (!stricmp(line, "nameserver"))
			{
				if (nscount >= 16)
				{
					continue;
				}

				strprintf(DNS.config.nameservers[nscount], INET6_ADDRSTRLEN + 1, NULL, "%s", p);

				nscount++;
			}
			else if (!stricmp(line, "interface"))
			{
				int port = 0;

				e = strchr(p, ' ');
				if (e)
				{
					*e = '\0';
					e++;

					while(e && *e)
					{
						if (*e < '0' || *e > '9')
						{
							break;
						}

						port = port * 10 + (*e - '0');

						e++;
					}
				}

				/* Ip and Port */
				strprintf(DNS.config.ifaceip, INET6_ADDRSTRLEN + 1, NULL, "%s", p);
				DNS.config.ifaceport = port;
			}else if (!stricmp(line, "options"))
			{
				char *v = strchr(p, ':');

				if (!v)
				{
					continue;
				}

				*v = '\0';
				v++;

				/* option */
				if (!stricmp(p, "recurser"))
				{
					if (v && *v == '1')
					{
						DNS.config.recurserenabled = 1;
					}
				}
				else if (!stricmp(p, "rtimeout"))
				{
					DNS.config.rtimeout = strtoul( v, NULL, 0 );
				}
				else if (!stricmp(p, "rcache"))
				{
					DNS.config.rcachesize = strtoul( v, NULL, 0 );
				}
				else{
				}
			}else
			{
#if 0
				XplConsolePrintf( "RESOLVER: Syntax error on line %ld of %s\n", lineNo, resolveConfigFile );
				goto ConfigError;
#endif
			}
		}
ConfigError:
		fclose( fp );
	}

	return;
}

// returns TRUE if the host name specified is a numeric address and fills out sa
EXPORT XplBool DNSNumericHost( const char *host, sa_family_t sa_family, struct sockaddr_storage *sa )
{
	struct addrinfo	hints, *info = NULL;

	if( host && sa )
	{
		memset( &hints, 0, sizeof( hints ) );
		hints.ai_flags = AI_NUMERICHOST;
		switch( sa_family )
		{
			case AF_UNSPEC:
			case AF_INET:
				hints.ai_family = AF_INET;
				hints.ai_protocol = SOCK_STREAM;
				getaddrinfo( host, NULL, &hints, &info );
				if( info )
				{
					memcpy( sa, info->ai_addr, sizeof( struct sockaddr_in ) );
					freeaddrinfo( info );
					return TRUE;
				}
				if( AF_INET == sa_family )
				{
					break;
				}
				// unspec fall

			case AF_INET6:
				hints.ai_family = AF_INET6;
				hints.ai_protocol = SOCK_STREAM;
				getaddrinfo( host, NULL, &hints, &info );
				if( info )
				{
					memcpy( sa, info->ai_addr, sizeof( struct sockaddr_in6 ) );
					freeaddrinfo( info );
					return TRUE;
				}
				break;

			default:
				printf("****** BAD Lookup FAMILY **** \n");
				break;
		}
	}
	return FALSE;
}

EXPORT DNSLookupResult DNSLookupA(const char *host, sa_family_t sa_family, struct sockaddr_storage *sa)
{
	DNSLookupResult	result = DNS_FAILURE;
	DNSAnswer		*answers, *a;

	if( !host || !strcmp( host, "0.0.0.0" ) )
	{
		return DNS_AUTHORITATIVE_FAILURE;
	}
	switch( sa_family )
	{
		case AF_INET:
			memset(sa, 0, sizeof(struct sockaddr_in));
			break;

		case AF_INET6:
			memset(sa, 0, sizeof(struct sockaddr_in6));
			break;

		case AF_UNSPEC:
			memset(sa, 0, sizeof(struct sockaddr_storage));
			break;
	}
	if( !DNSStartCount )
	{
		return DNS_FAILURE;
	}

	switch( sa_family )
	{
		case AF_UNSPEC:
		case AF_INET:
			result = CacheAnswerFind( host, &answers, DNS_TYPE_A );
			if( DNS_FAILURE < result )
			{
				sa_family = AF_INET;
				break;
			}
			if( AF_INET == sa_family )
			{
				break;
			}
			// unspec fall

		case AF_INET6:
			result = CacheAnswerFind( host, &answers, DNS_TYPE_AAAA );
			break;
	}

	for(a=answers;a;a=a->next)
	{
		if( DNS_ADDRESS == a->type )
		{
			if( sa_family == a->sa->sa_family )
			{
				switch( sa_family )
				{
					case AF_INET:
						memcpy( sa, a->sin, sizeof( struct sockaddr_in ) );
						break;

					case AF_INET6:
						memcpy( sa, a->sin6, sizeof( struct sockaddr_in6 ) );
						break;
				}
				DNSFreeAnswers( answers );
				return result;
			}
		}
	}
	DNSFreeAnswers( answers );
	return result;
}

EXPORT DNSLookupResult DNSLookup(const char *host, DNSQueryType type, DNSAnswer **answers)
{
	*answers=NULL;
	if( !DNSStartCount )
	{
		return DNS_FAILURE;
	}

	return (CacheAnswerFind( host, answers, type));
}

static DNSLookupResult ReverseLookup( struct sockaddr *sa, const char *zone, DNSAnswer **answers )
{
	int				l;
	char			name[1024];
	char			b;

	if( answers )
	{
		*answers = NULL;
		if( sa && zone )
		{
			switch( sa->sa_family )
			{
				case AF_INET:
					strprintf( name, sizeof( name ), NULL, "%d.%d.%d.%d.%s",
							   ((struct sockaddr_in *)sa)->sin_addr.s_impno,
							   ((struct sockaddr_in *)sa)->sin_addr.s_lh,
							   ((struct sockaddr_in *)sa)->sin_addr.s_host,
							   ((struct sockaddr_in *)sa)->sin_addr.s_net,
							   zone );
					return DNSLookup( name, DNS_TYPE_PTR, answers );

				case AF_INET6:
					// reverse nibbles of IP6 address 32 nibbles
					*name = '\0';
					// address is already in network order in structure, perfect
					for(l=0;l<16;l++)
					{
						b = ((struct sockaddr_in6 *)sa)->sin6_addr.s6_addr[l];
						strcatf( name, sizeof( name ), NULL, "%x.%x", (b >> 8) & 0x0f, b & 0x0f );
					}
					return DNSLookup( name, DNS_TYPE_PTR, answers );
			}
		}
	}
	return DNS_FAILURE;
}

static void _FreeAnswer( DNSAnswer *answer )
{
	if( !XplSafeDecrement( answer->useCount ) )
	{
		if( answer->state == ANSWER_STATE_FREE )
		{
			MemFree( answer );
		}
	}
}

// sa    : IP to look up
// returns SUCCESS if there is a matching reverse record for this address
// if confirm is set, confirm the forward lookup of each host found
// answers is optional and may be NULL if you don't want all of the answers (hosts)
EXPORT DNSLookupResult DNSReverseLookup( XplSockAddr *sa, XplBool confirm, DNSAnswer **answers )
{
	DNSAnswer 		*hosts, **ap, *addresses, *an;
	DNSLookupResult	result;

	if( answers )
	{
		*answers = NULL;
	}
	hosts = NULL;
	if( sa )
	{
		switch( sa->sa.sa_family )
		{
			case AF_INET:
				result = ReverseLookup( &sa->sa, "in-addr.arpa", &hosts );
				break;

			case AF_INET6:
				result = ReverseLookup( &sa->sa, "ip6.arpa", &hosts );
				break;

			default:
				return DNS_FAILURE;
		}
		if( !hosts )
		{
			return result;
		}

		if( confirm )
		{
            int confirmed_count = 0;
            DNSAnswer *confirmed_answer;

			for(ap=&hosts;(*ap);)
			{
				XplBool	confirmed = FALSE;

				if( (*ap)->name )
				{
					// Forward-confirmed
					DNSLookup( (*ap)->name, (sa->sa.sa_family == AF_INET) ? DNS_TYPE_A : DNS_TYPE_AAAA, &addresses );
					for(an=addresses;an;an=an->next)
					{
						if( an->sa && ( sa->sa.sa_family == an->sa->sa_family ) )
						{
							switch( sa->sa.sa_family )
							{
								case AF_INET:
									if( !memcmp( &sa->sin.sin_addr, &an->sin->sin_addr, sizeof( struct in_addr ) ) )
									{
										confirmed = TRUE;
									}
									break;

								case AF_INET6:
									if( !memcmp( &sa->sin6.sin6_addr, &an->sin6->sin6_addr, sizeof( struct in6_addr ) ) )
									{
										confirmed = TRUE;
									}
									break;
							}
						}
					}
					DNSFreeAnswers( addresses );
				}
				if( confirmed )
				{
					an = *ap;
                    
                    ++confirmed_count;

                    // if it requires answers back
                    // it will return duplicated list
                    if (answers)
                    {
                        confirmed_answer = MemMallocEx( NULL, sizeof( DNSAnswer ) + strlen( an->name ) + 1, NULL, FALSE, TRUE );
                        if (confirmed_answer)
                        {
                            XplSafeInit( confirmed_answer->useCount, 1 );

                            confirmed_answer->state = ANSWER_STATE_FREE;
                            confirmed_answer->type = DNS_NAME;
                            confirmed_answer->name = confirmed_answer->data;
                            strcpy( confirmed_answer->name, an->name );
                            confirmed_answer->next = *answers;
                            *answers = confirmed_answer;
                        }

                    }
				}

                // next
				ap = &(*ap)->next;
			}

            // free 
			DNSFreeAnswers( hosts );

            // set confirmed list
            return (confirmed_count) ? result : DNS_FAILURE;
		}
		if( answers )
		{
			*answers = hosts;
		}
		else
		{
			DNSFreeAnswers( hosts );
		}
		return result;
	}
	return DNS_FAILURE;
}

// sa		: IP to look up
// zone		: RBL zone
// answers	: Response
EXPORT DNSLookupResult DNSRBLLookup( struct sockaddr *sa, const char *zone, DNSAnswer **answers )
{
	int						l;
	char					name[1024];
	char					b;

	*answers = NULL;

	if( sa && zone )
	{
		switch( sa->sa_family )
		{
			case AF_INET:
				strprintf( name, sizeof( name ), NULL, "%d.%d.%d.%d.%s",
						   ((struct sockaddr_in *)sa)->sin_addr.s_impno,
						   ((struct sockaddr_in *)sa)->sin_addr.s_lh,
						   ((struct sockaddr_in *)sa)->sin_addr.s_host,
						   ((struct sockaddr_in *)sa)->sin_addr.s_net,
						   zone );
				return DNSLookup( name, DNS_TYPE_A, answers );

			case AF_INET6:
				// reverse nibbles of IP6 address 32 nibbles
				*name = '\0';
				// address is already in network order in structure, perfect
				for(l=0;l<16;l++)
				{
					b = ((struct sockaddr_in6 *)sa)->sin6_addr.s6_addr[l];
					strcatf( name, sizeof( name ), NULL, "%x.%x", (b >> 8) & 0x0f, b & 0x0f );
				}
				return DNSLookup( name, DNS_TYPE_A, answers );

			default:	// stupid warnings
				break;
		}
	}
	return DNS_FAILURE;
}

// host		: Host to look up
// zone		: DBL zone
// zoneRB	: RBL zone if host is a numeric address, can be NULL (URI RBL)
// answers	: Response
EXPORT DNSLookupResult DNSDBLLookup( const char *host, const char *zone, const char *zoneRBL, DNSAnswer **answers )
{
	struct sockaddr_storage	sa;
	char					name[1024];

	*answers=NULL;

	if( host && zone )
	{
		if( DNSNumericHost( host, AF_UNSPEC, &sa ) )
		{
			return DNSRBLLookup( (struct sockaddr *)&sa, zoneRBL, answers );
		}
		strprintf( name, sizeof( name ), NULL, "%s.%s", host, zone );
		return DNSLookup( name, DNS_TYPE_A, answers );
	}
	return DNS_FAILURE;
}

EXPORT void DNSFreeAnswers( DNSAnswer *answers )
{
	DNSAnswer *next;

	while( answers )
	{
		next = answers->next;
		_FreeAnswer( answers );
		answers = next;
	}
}

int DNSStart( void )
{
	int l;

	if( !DNSStartCount++ )
	{
		XplSafeInit( DNS.cacheEntries, 0 );
		XplSafeInit( DNS.cached, 0 );
		XplSafeInit( DNS.resolved, 0 );
		XplSafeInit( DNS.lookup, 0 );
		for(l=0;l<MAX_CACHE_HASH;l++)
		{
			XplLockInit( &DNS.cacheHash[l].lock );
			DNS.cacheHash[l].list = NULL;
			XplLockInit( &DNS.answerHash[l].lock );
			DNS.answerHash[l].list = NULL;
		}
		XplLockInit( &DNS.hosts.lock );
		DNS.hosts.list = NULL;
		DNS.hostTime = 0;
		DNS.timeout = RESOLVER_TIMEOUT;

		ReadResolverConfig();

		DNSLocalAddr.s_addr = inet_addr("127.0.0.1");

		DNS.resolve = Resolve;

#ifndef NO_LINUX_ONLY
		/* Enable recurser from config */
		if (DNS.config.recurserenabled)
		{
			AttachRecurser();
		}
#endif

		if( 0 == res_init() )
		{
			return TRUE;
		}
		return FALSE;
	}
	return TRUE;
}

void DNSStop( void )
{
	if( !--DNSStartCount )
	{
		ClearCache();

#ifndef NO_LINUX_ONLY
		if (DNS.config.recurserenabled)
		{
			DetachRecurser();
		}
#endif
	}
}

#ifndef NO_LINUX_ONLY
/*
   Recurser Ex functions
*/
static DNSLookupResult ResolveEx( unsigned char *name, int rtype, RHeader *answer, int *size, unsigned char **bp )
{
	int  l, err;
	DNSLookupResult result;

    memset( answer, 0, sizeof( RHeader ) );

	*size = (int)sizeof(RHeader);

	err = DnsRQueryPacket(name, rtype, (char *)answer, size);

	if (err)
	{
		// NXDOMAIN/NSRL_DETECTED
		if (3 == err)
		{
			//
		}

		err = DNS_FAILURE;
	}

	if( answer->flags & F_AUTHORITATIVE )
	{
		result = DNS_AUTHORITATIVE_SUCCESS;
	}
	else
	{
		result = DNS_SUCCESS;
	}

	if( !answer->ancount && !answer->nscount )
	{
#ifdef DEBUG_SEARCH
		XplConsolePrintf( "RESOLVE: %s has no answers\n", name );
#endif

		return result;
	}

	// process questions
	*bp = answer->buffer;
	for(l=0;l<answer->qdcount;l++)
	{
		DNSName( bp, (unsigned char *)answer, *size, NULL );
		DNSShort( bp, (unsigned char *)answer, *size, NULL );
		DNSShort( bp, (unsigned char *)answer, *size, NULL );
	}

	if( *bp ){
		return result;
	}
#ifdef DEBUG_SEARCH
		XplConsolePrintf( "RESOLVE: %s failed to decode answer\n", name );
#endif
	*size=0; // todo : useless?
	return DNS_FAILURE;
}

EXPORT int AttachRecurser(void)
{
	LoadNSRL(NULL, NULL);
	InitRecurserEx(SearchNSRL, DNS.config.rtimeout, DNS.config.rcachesize);

	if (DNS.config.ifaceip[0])
	{
		SetIface(DNS.config.ifaceip, (uint16)DNS.config.ifaceport);
	}

	DNS.resolve = ResolveEx;

	return(0);
}

EXPORT void DetachRecurser(void)
{
	// Set back to orignal as soon as detaching
	DNS.resolve = Resolve;

	DestroyRecurser();
	UnLoadNSRL();
}
#endif

/*
   DNS Stats
*/
EXPORT int DNSStats( unsigned long *entries, unsigned long *cached, unsigned long *resolved, unsigned long *lookup )
{
	if( entries )
	{
		*entries = XplSafeRead( DNS.cacheEntries );
	}
	if( cached )
	{
		*cached = XplSafeRead( DNS.cached );
	}
	if( resolved )
	{
		*resolved = XplSafeRead( DNS.resolved );
	}
	if( lookup )
	{
		*lookup = XplSafeRead( DNS.lookup );
	}
	return 0;
}

