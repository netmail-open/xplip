#include <xplip.h>

/* Get family from XplSockAddr
 * Accepts: XplSockAddr
 * Returns: family, always
 */

EXPORT sa_family_t XplSockAddrFamily(XplSockAddr *sa)
{
	return sa->sa.sa_family;
}


/* Get IP port from XplSockAddr
 * Accepts: XplSockAddr
 * Returns: port number on success, (uint16)(-1) on failure
 */

EXPORT uint16 XplSockAddrGetPort(XplSockAddr *sa)
{
	DebugAssert(sa);
	switch(XplSockAddrFamily(sa))
	{
		case AF_INET:
			return ntohs(((struct sockaddr_in *)sa)->sin_port);
		case AF_INET6:
			return ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
		case AF_UNSPEC:
			break;
		default:
			DebugAssert(0);	// invalid address family?  (at least one we don't handle)
			break;
	}
	DebugPrintf("%s", "Unable to extract port from socket address\n");
	return -1;
}

/* Set IP port in XplSockAddr
 * Accepts: XplSockAddr
 * Returns: TRUE on success, FALSE on failure
 */

EXPORT XplBool XplSockAddrSetPort(XplSockAddr *sa, uint16 port)
{
	DebugAssert(sa);
	switch(XplSockAddrFamily(sa))
	{
		case AF_INET:
			((struct sockaddr_in *)sa)->sin_port = htons( port );
			return TRUE;
		case AF_INET6:
			((struct sockaddr_in6 *)sa)->sin6_port = htons( port );
			return TRUE;
		case AF_UNSPEC:
			break;
		default:
			DebugAssert(0);	// invalid address family?  (at least one we don't handle)
			break;
	}
	DebugPrintf("%s", "Unable to set port in socket address\n");
	return FALSE;
}

/* Get IP address string from XplSockAddr
 * Accepts: XplSockAddr
 *		buffer to write IP address string
 *		length of IP address string
 * Returns: TRUE on success, FALSE on failure
 */

EXPORT XplBool XplSockAddrString(XplSockAddr *sa, char *buf, size_t buflen)
{
	DebugAssert(sa);
	switch(XplSockAddrFamily(sa))
	{
		case AF_INET:
			if(!getnameinfo(&sa->sa, sizeof(struct sockaddr_in), buf, buflen, NULL, 0, NI_NUMERICHOST)) {
				return TRUE;
			}
			break;

		case AF_INET6:
			if(!getnameinfo(&sa->sa, sizeof(struct sockaddr_in6), buf, buflen, NULL, 0, NI_NUMERICHOST)) {
				return TRUE;
			}
			break;

		case AF_UNSPEC:
			return FALSE;

		default:
			DebugAssert(0);	// invalid address family?  (at least one we don't handle)
			break;
	}
	DebugPrintf("%s", "Unable to translate socket address to string\n");
	return FALSE;
}


/* Get printable string from XplSockAddr
 * Accepts: XplSockAddr
 *		buffer to write IP address string
 *		length of IP address string
 * Returns: string, always
 */

EXPORT char *XplSockAddrToString(XplSockAddr *sa, char *buf, size_t buflen)
{
	return XplSockAddrString(sa, buf, buflen) ? buf : "UNKNOWN";
}


/* Provision a XplSockAddr from a string containing a purported address
 * Accepts: XplSockAddr to provision
 *		string
 * Returns: TRUE on success, FALSE on failure
 */

XplBool XplProvisionSockAddr(XplSockAddr *sa, char *address)
{
	struct addrinfo			hints, *info;

	if(!address)
	{
		return FALSE;
	}
	memset(sa, 0, sizeof(XplSockAddr));

	info = NULL;
	memset(&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICHOST;
	if( !getaddrinfo( address, NULL, &hints, &info ) )
	{
		switch( info->ai_family )
		{
			case AF_INET:
			case AF_INET6:
				memcpy( sa, info->ai_addr, info->ai_addrlen );
				freeaddrinfo( info );
				return TRUE;
		}
		freeaddrinfo( info );
	}
	return FALSE;
}


/* Compare XplSockAddr
 * Accepts: destination XplSockAddr
 *		source XplSockAddr
 * Returns: TRUE if match, FALSE otherwise
 */

EXPORT void XplCopySockAddr(XplSockAddr *dst, XplSockAddr *src)
{
	memset(dst, 0, sizeof(XplSockAddr));
	switch(XplSockAddrFamily(src)) {
	case AF_INET:
		memcpy(&dst->sa4, &src->sa4, sizeof(src->sa4));
		break;
	case AF_INET6:
		memcpy(&dst->sa6, &src->sa6, sizeof(src->sa6));
		break;
	default:
		memcpy(dst, src, sizeof(XplSockAddr));
		break;
	}
}


/* Compare XplSockAddr
 * Accepts: first XplSockAddr
 *		second XplSockAddr
 * Returns: TRUE if match, FALSE otherwise
 */

EXPORT XplBool XplEquivalentSockAddr(XplSockAddr *sa1, XplSockAddr *sa2)
{
	if(XplSockAddrFamily(sa1) == XplSockAddrFamily(sa2)) {
		switch(XplSockAddrFamily(sa1))
		{
			case AF_INET:
				if(!memcmp(&sa1->sa4.sin_addr, &sa2->sa4.sin_addr, sizeof(sa1->sa4.sin_addr))) {
					return TRUE;
				}
				break;

			case AF_INET6:
				if(!memcmp(&sa1->sa6.sin6_addr, &sa2->sa6.sin6_addr, sizeof(sa1->sa6.sin6_addr))) {
					return TRUE;
				}
				break;

			case AF_UNSPEC:
				return FALSE;

			default:
				DebugPrintf("Unable to compare address family %d\n", (int) XplSockAddrFamily(sa1));
				DebugAssert(0);	// invalid address family?  (at least one we don't handle)
				break;
		}
	}
	return FALSE;
}

EXPORT XplBool XplSockAddrIsLocal(XplSockAddr *sa)
{
	if (!sa) {
		return(FALSE);
	}

	return(XplIsLocalSockaddr(&sa->sa));
}

