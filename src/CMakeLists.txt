add_library(xplip SHARED
	resolve.c
	ip.c
	recurse.c
	recurseutil.c
	sockaddr.c
	nsrl.c
)


set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ALL_CFLAGS} ${PTHREAD_CFLAGS} ${OPENSSL_CFLAGS}")

find_library(MEMMGR_LIBRARY
  NAMES libmemmgr memmgr
)

target_link_libraries(xplip
	xplmem${BIT}
	${RESOLV_LIBS}
	${OPENSSL_LIBS}
	${WINSOCK_LIBS}
	${RESOLV_LIBS}
)

install(TARGETS xplip DESTINATION /usr/lib)
