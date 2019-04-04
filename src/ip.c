#include <xplip.h>
#include <xplerr.h>
#include <stdio.h>
#include <ctype.h>
#include <xplmem.h>

struct XplInterface *XplInterfaceList = NULL;
int XplIpInitialized = 0;

#if defined(LINUX) || defined(S390RH) || defined(SOLARIS) || defined(MACOSX)
#include <sys/utsname.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <unistd.h>
#include <fcntl.h>

# ifdef LINUX
#  include <sys/epoll.h>
# endif
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netdb.h>



int
XplSocketSetMode( XplSocket sock, XplSocketMode mode)
{
    int ccode;

    switch (mode) {
        case XPL_SOCKET_MODE_BLOCKING: {
            ccode = fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) & ~O_NONBLOCK);
            break;
        }

        case XPL_SOCKET_MODE_NON_BLOCKING: {
            ccode = fcntl(sock, F_SETFL, O_NONBLOCK | fcntl(sock, F_GETFL, 0));
            break;
        }

        case XPL_SOCKET_MODE_DISABLE_NAGLE: {
			int flag = 1;
			ccode = setsockopt( sock, IPPROTO_TCP, TCP_NODELAY, ( unsigned char *)&flag, sizeof( int ) );
            break;
        }

        default: {
            errno = EINVAL;
            ccode = XPL_SOCKET_ERROR;
        }
    }

    return(ccode);
}

int
XplIpRead(XplSocket socket, char *buf, int len, unsigned long timeout )
{
	int				rc;
	struct pollfd	pfd;

	/* All sockets are closed when exiting. Closed socket will error on read. */
	pfd.fd		= (int)socket;
	pfd.events	= POLLIN;

	rc = poll( &pfd, 1, timeout );
	if (rc > 0) {
		/*success */
		/* see if an error ocurred on this socket */
		if (!(pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {

			XPLIPRead_Again:

			rc = recv((int)socket, buf, len, 0);
			if (rc >= 0) {
				/* success  */
				return(rc);
			} else if (errno == EINTR) {
				goto XPLIPRead_Again;
			}

			/* read error(-1) or end of connection (0) */
			return(rc);
		}

		/* pfd.revents error received */
		return(-1);
	} else if (rc == 0) {
		/* poll timeout */
		return(-1);
	}

	return(-1);
}

int
XplIpReadFrom(XplSocket socket, char *buf, int len, int flags, struct sockaddr *from, socklen_t *fromlen, unsigned long timeout )
{
	int				rc;
	struct pollfd	pfd;

	/* All sockets are closed when exiting. Closed socket will error on read. */
	pfd.fd		= (int)socket;
	pfd.events	= POLLIN;

	rc = poll( &pfd, 1, timeout );
	if (rc > 0) {
		/*success */
		/* see if an error ocurred on this socket */
		if (!(pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {

			XPLIPRead_Again:

			rc = recvfrom((int)socket, buf, len, flags, from, fromlen);
			if (rc >= 0) {
				/* success  */
				return(rc);
			} else if (errno == EINTR) {
				goto XPLIPRead_Again;
			}

			/* read error(-1) or end of connection (0) */
			return(rc);
		}

		/* pfd.revents error received */
		return(-1);
	} else if (rc == 0) {
		/* poll timeout */
		return(-1);
	}

	return(-1);
}

/* Linux version */
XplInterface * XplGetInterfaceList(void)
{
	int						flags;
	int						myflags;
	struct ifconf			ifc;
	struct ifreq			*ifr;
	struct ifreq			ifrcopy;

	struct XplInterface		*ifi;
	struct XplInterface		*ifihead;
	struct XplInterface		**ifipnext;
	int						sockfd		= socket(AF_INET, SOCK_DGRAM, 0); // TODO: ipv6 ?
	int						len			= 100 * sizeof(struct ifreq);

	if (sockfd < 0)
	{
		perror("open 'socket' error");
		return(NULL);
	}

	memset(&ifc, 0, sizeof(ifc));

	ifc.ifc_len	= len;
	ifc.ifc_req	= MemMallocWait(len);

	if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
		perror("getifi_info ioctl error");
	}

	ifihead		= NULL;
	ifipnext	= &ifihead;

	for (ifr = ifc.ifc_req; (char *) ifr < (char *) ifc.ifc_req + ifc.ifc_len; ifr++) {
		len = sizeof(struct sockaddr);

#ifdef HAVE_SOCKADDR_SA_LEN
		if (len < ifr->ifr_addr.sa_len) {
			len = ifr->ifr_addr.sa_len;
		}
#else
# ifdef AF_INET6
		if (AF_INET6 == ifr->ifr_addr.sa_family) {
			len = sizeof(struct sockaddr_in6);
		}
# endif
#endif
		switch (ifr->ifr_addr.sa_family) {
			case AF_INET:
			case AF_INET6:
				break;

			default:
				/* We only care about IPv4 and IPv6 addresses */
				continue;
		}

		myflags = 0;

		ifrcopy = *ifr;
		ioctl(sockfd, SIOCGIFFLAGS, &ifrcopy); // TODO ifreq ipv6 ! not supported?
		flags = ifrcopy.ifr_flags;
		if ((flags & IFF_UP) == 0) {
			/* ignore if interface not up */
			continue;
		}

		ifi = MemMalloc(sizeof(struct XplInterface));
		memset(ifi, 0, sizeof(struct XplInterface));

		/* Read the hardware address (mac address) */
#ifdef SIOCGIFHWADDR
		ifrcopy = *ifr;
		ioctl(sockfd, SIOCGIFHWADDR, &ifrcopy);
		memcpy((void*) &ifi->macAddr[0], (void *) &ifrcopy.ifr_ifru.ifru_hwaddr.sa_data[0], 6 );
#endif

		*ifipnext = ifi; /* prev points to this new one */
		ifipnext = &ifi->next; /* pointer to next one goes here */

		switch(ifr->ifr_addr.sa_family) {
			case AF_INET:
				if(ifi->sa == NULL) {
					ifi->salen= sizeof(struct sockaddr_in);
					ifi->sa = MemCalloc(1, (size_t) ifi->salen);
					memcpy(ifi->sa, (struct sockaddr_in *)&ifr->ifr_addr, sizeof(struct sockaddr_in));
				}
				break;
			case AF_INET6:
				if(ifi->sa == NULL) {
					ifi->salen= sizeof(struct sockaddr_in6);
					ifi->sa = MemCalloc(1, (size_t) ifi->salen);
					memcpy(ifi->sa, (struct sockaddr_in6 *)&ifr->ifr_addr, sizeof(struct sockaddr_in6));
				}
				break;
		}
	}
	MemRelease(&ifc.ifc_req);

	close(sockfd);

	return(ifihead);
}

#elif defined(WIN32)

#include <iphlpapi.h>
#include <winioctl.h>
#include <ws2tcpip.h>
#include <iptypes.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

EXPORT XplInterface * XplGetInterfaceList(void){ /* Windows version*/

	 struct XplInterface *ifi;
	 struct XplInterface *ifihead;
	 struct XplInterface **ifipnext;
	 struct sockaddr_in *sinptr;

	 WORD versionRequested;
     int wsError;
     WSADATA winsockData;
     SOCKET s;
     DWORD bytesReturned;

     INTERFACE_INFO localAddr[64];  // use #define MLICENSE_MAX_IPS	64
     int i,numLocalAddr;

	 ifihead=NULL;
	 ifipnext=&ifihead;

     versionRequested = MAKEWORD(2, 2); /* needed? */

     wsError = WSAStartup(versionRequested, &winsockData);/* needed? */

     if (wsError)
     {
          return (ifihead);
     }

     if((s = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, 0)) == INVALID_SOCKET)
     {
          WSACleanup();
          return (ifihead);
        }

     /* Enumerate all IP Interface */
     wsError = WSAIoctl(s, SIO_GET_INTERFACE_LIST, NULL, 0, &localAddr,
                      sizeof(localAddr), &bytesReturned, NULL, NULL);
     if (wsError == SOCKET_ERROR)
     {
          XplConsolePrintf("WSAIoctl fails with error %d\n", GetLastError());
          closesocket(s);
          WSACleanup();
          return (ifihead);
     }

     closesocket(s);

     // Copy interface information
     numLocalAddr = (bytesReturned/sizeof(INTERFACE_INFO));

	 for ( i=0; i<numLocalAddr; i++)
     {
		if ((localAddr[i].iiFlags & IFF_UP) == 0) {
			/* ignore if interface not up */
	        continue;
	     }
		/*check family */
		if (localAddr[i].iiAddress.Address.sa_family != AF_INET) {
			/* ignore if not desired address family */
	        continue;
	    }

		ifi = MemMalloc(sizeof(struct XplInterface));
	    memset(ifi, 0, sizeof(struct XplInterface));
	    *ifipnext = ifi; /* prev points to this new one */
	    ifipnext = &ifi->next; /* pointer to next one goes here */

        sinptr = (struct sockaddr_in *)&localAddr[i].iiAddress;

     	if(ifi->sa == NULL) {
			ifi->salen= sizeof(struct sockaddr_in);
        	ifi->sa = MemCalloc(1, (size_t) ifi->salen);
        	memcpy(ifi->sa, sinptr, sizeof(struct sockaddr_in));
	    }

     }

     WSACleanup();
	 return (ifihead);
}

EXPORT XplInterface *
XplGetAdapterList(void)
{
	struct XplInterface *adi;
	struct XplInterface *adihead;
	struct XplInterface **adipnext;
	DWORD dwStatus ;
	PIP_ADAPTER_INFO pAdapterInfo ;
	IP_ADAPTER_INFO adapterInfo[64];
	DWORD dwBufLen;
	adihead=NULL;
	adipnext=&adihead;

	dwBufLen = sizeof(adapterInfo);

	dwStatus = GetAdaptersInfo( adapterInfo,&dwBufLen);

    if (dwStatus != ERROR_SUCCESS)
    {
		XplConsolePrintf("GetAdaptersInfo failed ith error %d\n", GetLastError());
        return (adihead);//NULL
    }

	pAdapterInfo = adapterInfo;

	for (pAdapterInfo; pAdapterInfo!=NULL; pAdapterInfo = pAdapterInfo->Next )
	{
		adi = MemMalloc(sizeof(struct XplInterface));
		memset(adi, 0, sizeof(struct XplInterface));
		*adipnext = adi;
		adipnext = &adi->next;
		memcpy((void*)&adi->macAddr[0],(void *)pAdapterInfo->Address, 6 );
	}
	return (adihead);
}



EXPORT int
XplSocketSetMode( XplSocket sock, XplSocketMode mode)
{
    int ccode;
    DWORD returned = 0;
    unsigned long nonblock;

    switch (mode) {
        case XPL_SOCKET_MODE_BLOCKING: {
            nonblock = 0;
			ccode = WSAIoctl(sock, FIONBIO, &nonblock, sizeof(nonblock), NULL, 0, &returned, NULL, NULL);
            break;
        }

        case XPL_SOCKET_MODE_NON_BLOCKING: {
            nonblock = 1;
			ccode = WSAIoctl(sock, FIONBIO, &nonblock, sizeof(nonblock), NULL, 0, &returned, NULL, NULL);
            break;
        }

        case XPL_SOCKET_MODE_DISABLE_NAGLE: {
			int flag = 1;
			ccode = setsockopt( sock, IPPROTO_TCP, TCP_NODELAY, ( unsigned char *)&flag, sizeof( int ) );
            break;
        }

        default: {
            errno = ENOSYS;
            return(XPL_SOCKET_ERROR);
        }
    }

    if (ccode != SOCKET_ERROR) {
        return(0);
    }

    errno = XplTranslateError(WSAGetLastError());
    return(-1);
}

EXPORT
int
XplIpRead(XplSocket socket, char *buf, int len, unsigned long timeout)
{
	int				rc;
	fd_set			readfds;
	struct timeval	sTimeout;  /* select style timeout */

	FD_ZERO(&readfds);
	FD_SET( (int)socket,&readfds);

	sTimeout.tv_sec = timeout / 1000;
	sTimeout.tv_usec = ( timeout - sTimeout.tv_sec ) * 1000;

	/* All sockets are closed when exiting.  */
	/* Closed sockets will error on read. */
	rc = select(FD_SETSIZE, &readfds, NULL,NULL, &sTimeout );
	if (rc > 0) {
		/*success - no special handling of read */
		return(recv((int)socket, buf, len, 0));
	}

	/* return -1 on timeout or select error  */
	return(-1);
}

EXPORT
int
XplIpReadFrom(XplSocket socket, char *buf, int len, int flags, struct sockaddr *from, socklen_t *fromlen, unsigned long timeout)
{
	int				rc;
	fd_set			readfds;
	struct timeval	sTimeout;  /* select style timeout */

	FD_ZERO(&readfds);
	FD_SET( (int)socket,&readfds);

	sTimeout.tv_sec = timeout / 1000;
	sTimeout.tv_usec = ( timeout - sTimeout.tv_sec ) * 1000;

	/* All sockets are closed when exiting.  */
	/* Closed sockets will error on read. */
	rc = select(FD_SETSIZE, &readfds, NULL,NULL, &sTimeout );
	if (rc > 0) {
		/*success - no special handling of read */
		return(recvfrom((int)socket, buf, len, flags, from, fromlen));
	}

	/* return -1 on timeout or select error  */
	return(-1);
}

#elif defined(NETWARE) || defined(LIBC)

#else
#error There is no ISO C99 error mapping interface defined for this platform.
#endif

/* non system specific  */
EXPORT int XplIpInit(void)
{
	if (!XplIpInitialized++) {
		XplInitWinSock()
		DNSStart();

		XplInterfaceList = XplGetInterfaceList();
	}
    return(0);
}

EXPORT int XplIpCleanup(void)
{
	if (!--XplIpInitialized) {
		XplWinIpCleanup()
		DNSStop();

		if (XplInterfaceList) {
			XplFreeInterfaceList(XplInterfaceList);
			XplInterfaceList = NULL;
		}
	}

	return(0);
}

// Currently just returns the local IP address as a string.  May change in the future

EXPORT int XplGetHostMachineID(char *buf, size_t buflen)
{
	struct sockaddr_storage sa;
	XplGetHostIPAddress(AF_UNSPEC, &sa);
	return getnameinfo((struct sockaddr *) &sa, sizeof(sa), buf, buflen, NULL, 0, NI_NUMERICHOST);
}

/* Set the port in an sa
 * Accepts: struct sockaddr_storage *
 * 			port number
 * Returns: TRUE on success, FALSE on failure
 */

EXPORT XplBool XplIPSockAddrSetPort( struct sockaddr *sa, uint16 port )
{
	XplBool ret;

	switch (sa->sa_family) {
	case AF_INET:
		( ( struct sockaddr_in * ) sa)->sin_port = htons( port );
		if( ( ( struct sockaddr_in * ) sa)->sin_port == htons( port ) ) {
			ret = TRUE;
			break;
		}
		DebugAssert( 0 ); // the port is too big for this family ( rodney )
		ret = FALSE;
		break;

	case AF_INET6:
		( ( struct sockaddr_in6 * ) sa )->sin6_port = htons( port );
		ret = TRUE;
		break;

	default:
		errno = EPROTONOSUPPORT;
		DebugAssert( 0 );  // this sa has a family we do not know what to do with ( rodney )
		ret = FALSE;
		break;
    }
	return ret;
}

EXPORT uint16 XplIPSockAddrGetPort( struct sockaddr *sa )
{
	switch (sa->sa_family) {
	case AF_INET:
		return ntohs( ( ( struct sockaddr_in * ) sa)->sin_port );

	case AF_INET6:
		return ntohs( ( ( struct sockaddr_in6 * ) sa )->sin6_port );

	default:
		errno = EPROTONOSUPPORT;
		DebugAssert( 0 );  // this sa has a family we do not know what to do with ( rodney )
		break;
    }
	return 0;
}

EXPORT void XplGetHostIPAddress(sa_family_t sa_family, struct sockaddr_storage *sa)
{
	XplInterface			*iface, *iflist;
	struct addrinfo			hints, *info;
	int						errcode;
	unsigned char			name[256];

	errno = 0;

	if (!sa) {
		return;
	}

	switch (sa_family) {
		case AF_INET:
			memset(sa, 0, sizeof(struct sockaddr_in));
			break;

		case AF_INET6:
			memset(sa, 0, sizeof(struct sockaddr_in6));
			break;

		case AF_UNSPEC:
			memset(sa, 0, sizeof(struct sockaddr_storage));
			break;

		default:
			return;
			break;
    }

	gethostname(name, sizeof(name));

	memset(&hints, 0, sizeof (hints));
	hints.ai_family = sa_family;

	info = NULL;
	errcode = getaddrinfo(name, NULL, &hints, &info);

	if (info) {
		if (!XplIsLoopbackAddress(info->ai_addr)) {
			switch (info->ai_family) {
				case AF_INET:
					if ((sa_family == AF_INET) || sa_family == AF_UNSPEC) {
						memcpy(sa, info->ai_addr, sizeof(struct sockaddr_in));
					}
					break;

				case AF_INET6:
					if ((sa_family == AF_INET6) || sa_family == AF_UNSPEC) {
						memcpy(sa, info->ai_addr, sizeof(struct sockaddr_in6));
					}
					break;
			}
		}
		freeaddrinfo(info);
	}

	iflist = XplGetInterfaceList();

	/*
		Walk through the local interfaces.  If one of them matches the address
		that was found above then return it.
	*/
	if (sa->ss_family) {
		if (!iflist) {
			/* We couldn't find any bound addresses, so trust the hostname */
			return;
		}

		for (iface = iflist; iface; iface = iface->next) {
			if (!iface->sa) continue;

			switch (iface->sa->ss_family) {
				case AF_INET:
					if (!memcmp(sa, iface->sa, sizeof(struct sockaddr_in))) {
						XplFreeInterfaceList(iflist);
						return;
					}
					break;

				case AF_INET6:
					if (!memcmp(sa, iface->sa, sizeof(struct sockaddr_in6))) {
						XplFreeInterfaceList(iflist);
						return;
					}
					break;
			}
		}
	}

	/*
		We didn't find a bound address that matched the hostname, so return the
		first address of the right address type that isn't a loopback.

		Loop twice because we prefer an IPv4 address over an IPv6 (for now).
		When we decide to prefer IPv6 just swap these 2 loops.
	*/
	if ((sa_family == AF_INET) || sa_family == AF_UNSPEC) {
		for (iface = iflist; iface; iface = iface->next) {
			if (!iface->sa || AF_INET != iface->sa->ss_family ||
				XplIsLoopbackAddress((struct sockaddr *)iface->sa)
			) {
				continue;
			}

			memcpy(sa, iface->sa, sizeof(struct sockaddr_in));
			XplFreeInterfaceList(iflist);
			return;
		}
	}

	if ((sa_family == AF_INET6) || sa_family == AF_UNSPEC) {
		for (iface = iflist; iface; iface = iface->next) {
			if (!iface->sa || AF_INET6 != iface->sa->ss_family ||
				XplIsLoopbackAddress((struct sockaddr *)iface->sa)
			) {
				continue;
			}

			memcpy(sa, iface->sa, sizeof(struct sockaddr_in6));
			XplFreeInterfaceList(iflist);
			return;
		}
	}

	XplFreeInterfaceList(iflist);
	iflist = NULL;

	/* still no adress return loopback */
	info = NULL;

	memset(&hints, 0, sizeof (hints));
	hints.ai_family = sa_family;
	hints.ai_flags = AI_NUMERICHOST;

	switch (sa_family) {
		case AF_INET:
		case AF_UNSPEC:
			getaddrinfo("127.0.0.1", NULL, &hints, &info);
			break;

		case AF_INET6:
			getaddrinfo("::1", NULL, &hints, &info);
			break;
	}

	if (info) {
		memcpy(sa, info->ai_addr, info->ai_addrlen);
		freeaddrinfo(info);
	}

	return;
}

EXPORT XplBool XplIsLoopbackAddress( struct sockaddr *sa )
{
	char	buffer[INET6_ADDRSTRLEN +1 ];

	if( sa )
	{
		switch( sa->sa_family )
		{
			case AF_INET:
				/* 127.127.127.127 is considered a non-local address for the sake of testing */
				if (0x7f7f7f7f == ((((struct sockaddr_in *)sa)->sin_addr.s_addr))) {
					return(FALSE);
				}

				if (127 == (((struct sockaddr_in *)sa)->sin_addr.s_net)) {
					return TRUE;
				}

				if (0 == ((struct sockaddr_in *)sa)->sin_addr.s_addr) {
					return TRUE;
				}
				break;

			case AF_INET6:
				getnameinfo(sa, sizeof(struct sockaddr), buffer, sizeof(buffer), NULL, 0, NI_NUMERICHOST);
				if (!strcmp("::1", buffer)) {
					return TRUE;
				}
				break;
		}
	}
	return FALSE;
}

EXPORT XplBool XplIsLocalSockaddr(struct sockaddr *sadr)
{
	struct XplInterface		*ifi, *freeifi;
	union {
		struct sockaddr		*sa;
		struct sockaddr_in	*sa4;
		struct sockaddr_in6	*sa6;
	} sa;
	XplBool					ret = FALSE;

	if(XplIsLoopbackAddress(sadr)) {
		ret = TRUE;
	}
	else {
		sa.sa = sadr;

		if (XplInterfaceList) {
			ifi = XplInterfaceList;
			freeifi = NULL;
		}
		else {
			ifi = freeifi = XplGetInterfaceList();
		}

		for ( ; ifi && !ret; ifi = ifi->next) {
			if (ifi->sa && (ifi->sa->ss_family == sadr->sa_family)) {
				switch(sadr->sa_family) {
				case AF_INET:
					if(!memcmp(&sa.sa4->sin_addr, &((struct sockaddr_in *) ifi->sa)->sin_addr, sizeof(sa.sa4->sin_addr))) {
						ret = TRUE;
					}
					break;
				case AF_INET6:
					if(!memcmp(&sa.sa6->sin6_addr, &((struct sockaddr_in6 *) ifi->sa)->sin6_addr, sizeof(sa.sa6->sin6_addr))) {
						ret = TRUE;
					}
					break;
				}
			}
		}
		if (freeifi) {
			XplFreeInterfaceList(freeifi);
		}
	}
	return ret;
}


//todo: ipv6
EXPORT XplBool XplIsLocalIPAddress(unsigned long Address)
{
	struct XplInterface		*ifi, *freeifi;
	struct sockaddr_in		sa;

	errno = 0;

	/* 127.127.127.127 is considered a non-local address for the sake of testing */
	if (0x7f7f7f7f == Address) {
		return(FALSE);
	}

	/* 127.*.*.* is local */
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = Address;
	if (XplIsLoopbackAddress( (struct sockaddr *)&sa)) {
		return(TRUE);
	}

	if (XplInterfaceList) {
		ifi = XplInterfaceList;
		freeifi = NULL;
	} else {
		ifi = freeifi = XplGetInterfaceList();
	}

	for ( ; ifi; ifi = ifi->next) {
		if ((ifi->sa) && ( ifi->sa->ss_family == AF_INET) ){
			if	(Address == ((struct sockaddr_in *) ifi->sa)->sin_addr.s_addr) {
				break;
			}
		}
	}

	if (freeifi) {
		XplFreeInterfaceList(freeifi);
	}

	return(ifi ? TRUE : FALSE);
}

EXPORT int XplFreeInterfaceList(struct XplInterface *list)
{

	XplInterface  *iface;

	while ((iface = list)) {
		list = iface->next;

		MemFree(iface->sa);
		MemFree(iface);
	}

	return 0;
}

EXPORT ssize_t XplIPAddrString(struct sockaddr *sa, char *buffer, size_t bufsize)
{
	return XplIPAddrString_EX(sa, buffer, bufsize, TRUE);
}

EXPORT ssize_t XplIPAddrString_EX(struct sockaddr *sa, char *buffer, size_t bufsize, XplBool withPort)
{
	int		r = 0;
	size_t	needed;
	char	host[256];
	char	serv[256];

	if (!sa || !buffer || !bufsize) {
		return(-(errno = EINVAL));
	}

	switch(sa->sa_family) {
		case AF_INET: {
			struct sockaddr_in		*sin = (struct sockaddr_in *) sa;

			if( !getnameinfo( sa, sizeof( struct sockaddr_in ), host, sizeof( host ), serv, sizeof( serv ), NI_NUMERICHOST|NI_NUMERICSERV ) )
			{
				if( sin->sin_port && withPort )
				{
					r = strprintf( buffer, bufsize, &needed, "%s:%s", host, serv );
				}
				else
				{
					r = strprintf( buffer, bufsize, &needed, "%s", host );
				}
				if( needed > bufsize )
				{
					*buffer = '\0';
					return -(errno=ENOSPC);
				}
				return r;
			}
			else
			{
				*buffer = '\0';
			}
			break;
		}
#ifdef AF_INET6
		case AF_INET6: {
			struct sockaddr_in6		*sin6 = (struct sockaddr_in6 *) sa;

			if( !getnameinfo( sa, sizeof( struct sockaddr_in6 ), host, sizeof( host ), serv, sizeof( serv ), NI_NUMERICHOST|NI_NUMERICSERV ) )
			{
				if( sin6->sin6_port && withPort )
				{
					r = strprintf( buffer, bufsize, &needed, "[%s]:%s", host, serv );
				}
				else
				{
					r = strprintf( buffer, bufsize, &needed, "%s", host );
				}
				if( needed > bufsize )
				{
					*buffer = '\0';
					return -(errno=ENOSPC);
				}
				return r;
			}
			else
			{
				*buffer = '\0';
			}
			break;
		}
#endif
		default:
			break;
	}
	return(-(errno = EAFNOSUPPORT));
}


EXPORT int XplStrToIPAddr(char *buffer, struct sockaddr *sa, socklen_t *saLen)
{
	union {
		struct sockaddr_in	v4;
	} sin;
	char					a[256];
	char					*c	= NULL;
#ifdef AF_INET6
	char					*b	= NULL;
	char					*port	= NULL;
	struct addrinfo			hints, *info, *i;
#endif
	if (!saLen) return(-(errno = EINVAL));
	strncpy(a, buffer, sizeof(a));

#ifdef AF_INET6
	/*
		IPv6 addresses must be wrapped in square brackets to specify a port in
		order to distinguish the colon for the port and the colons in the
		address.
	*/
	if ((c = strrchr(a, ']')) && (c = strchr(c + 1, ':'))) {
		if( b = strchr(a, '[') )
		{
			b++;
			if( b >= c )
			{
				return -(errno = EINVAL);
			}
			buffer = b;
		}
		*c = '\0';
		port = c+1;
	}

	memset( &hints, 0, sizeof( hints ) );
	info = NULL;
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if( !getaddrinfo( buffer, port, &hints, &info ) )
	{
		errno = ENOENT;
		for(i=info;i;i=i->ai_next )
		{
			if( i->ai_family == AF_INET6 )
			{
				if( *saLen >= i->ai_addrlen )
				{
					if( sa )
					{
						memcpy( sa, i->ai_addr, i->ai_addrlen );
					}
					errno = 0;
				}
				else
				{
					*saLen = i->ai_addrlen;
					errno = ENOSPC;
				}
			}
		}
		freeaddrinfo( info );
		if (c) *c = ':';
		return -(errno);
	}
	if (c) *c = ':';
#endif

	memset(&sin.v4, 0, sizeof(sin.v4));
	sin.v4.sin_family = AF_INET;
	if ((c = strrchr(a, ':'))) {
		*c = '\0';
		sin.v4.sin_port = htons(atoi(c + 1));
	}

	sin.v4.sin_addr.s_addr = inet_addr(a);
	if (INADDR_NONE == sin.v4.sin_addr.s_addr) {
		DNSLookupA(a, AF_INET, (struct sockaddr_storage*)&sin.v4);
	}

	if (!sin.v4.sin_addr.s_addr) {
		return(-(errno = ENXIO));
	}

	if (*saLen < sizeof(sin.v4)) {
		*saLen = sizeof(sin.v4);
		return(-(errno = ENOSPC));
	}

	*saLen = sizeof(sin.v4);
	if (sa) memcpy(sa, &sin.v4, sizeof(sin.v4));

	return(0);
}

EXPORT int XplIPAddrCmp(struct sockaddr *a, struct sockaddr *b, XplBool checkPort)
{
	if (!a || !b) {
		return(-1);
	}

	if (a->sa_family != b->sa_family) {
		return(-1);
	}

	switch (a->sa_family) {
		case AF_INET:
			if (checkPort &&
				((struct sockaddr_in *) a)->sin_port != ((struct sockaddr_in *) b)->sin_port
			) {
				return(-1);
			}

			return( ntohl(((struct sockaddr_in *) a)->sin_addr.s_addr) -
					ntohl(((struct sockaddr_in *) b)->sin_addr.s_addr));

#ifdef AF_INET6
		case AF_INET6:
			if (checkPort &&
				((struct sockaddr_in6 *) a)->sin6_port != ((struct sockaddr_in6 *) b)->sin6_port
			) {
				return(-1);
			}

			return(memcmp(	((struct sockaddr_in6 *) a)->sin6_addr.s6_addr,
							((struct sockaddr_in6 *) b)->sin6_addr.s6_addr,
							sizeof(((struct sockaddr_in6 *) b)->sin6_addr.s6_addr)));
#endif

		default:
			DebugAssert(0);
			return(-1);
	}
}

EXPORT uint32 XplIPv4Addr(struct sockaddr *sa)
{
	if (!sa) {
		errno = EINVAL;
		return(0);
	} else if (AF_INET != sa->sa_family) {
#ifdef EAFNOSUPPORT
		errno = EAFNOSUPPORT;
#else
		errno = EINVAL;
#endif
		return(0);
	}

	return((uint32) ((struct sockaddr_in *) sa)->sin_addr.s_addr);
}

EXPORT socklen_t XplIPAddrSize(struct sockaddr *sa)
{
	if (!sa) return(0);

	switch (sa->sa_family) {
		case AF_INET:
			return(sizeof(struct sockaddr_in));
#ifdef AF_INET6
		case AF_INET6:
			return(sizeof(struct sockaddr_in6));
#endif

		default:
#ifdef EAFNOSUPPORT
			errno = EAFNOSUPPORT;
#else
			errno = EINVAL;
#endif
			break;
	}

	return(0);
}

