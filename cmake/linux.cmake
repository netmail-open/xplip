find_library(MEMMGR		memmgr libmemmgr		HINT /usr/lib/ NO_DEFAULT_PATH)

#TODO write detection utility
set(HAVE_UNIX_SOCKETS           1)

set (RESOLV_LIBS                resolv)
