noinst_LIBRARIES = libbip.a

libbip_a_SOURCES = \
	bip.c bip.h \
	bucket.c bucket.h \
	conf.y lex.l \
	connection.c connection.h \
	defaults.h \
	irc.c irc.h \
	line.c line.h \
	log.c log.h \
	md5.c md5.h \
	path_util.c path_util.h \
	poller.c poller.h \
	tuple.h \
	util.c util.h

libbip_a_CFLAGS = $(OPENSSL_CFLAGS) $(AM_CFLAGS)

bin_PROGRAMS = bip bipmkpw

bip_SOURCES = bip_main.c
bip_CFLAGS = $(OPENSSL_CFLAGS) $(AM_CFLAGS)
bip_LDADD = libbip.a $(OPENSSL_LIBS)

bipmkpw_SOURCES = bipmkpw.c md5.c util.c
bipmkpw_CFLAGS = $(OPENSSL_CFLAGS) $(AM_CFLAGS)
bipmkpw_LDADD = libbip.a $(OPENSSL_LIBS)

AM_YFLAGS= -d
BUILT_SOURCES = conf.c conf.h lex.c

AM_CFLAGS=-Wall -Wextra -Werror
