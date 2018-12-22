noinst_LIBRARIES = libbip.a libbiplex.a

libbiplex_a_SOURCES = \
	conf.y lex.l

# Not adding AM_CFLAGS here, because many debian flex releases generate code
# that comparessigned and unsigned integers.
libbiplex_a_CFLAGS = $(OPENSSL_CFLAGS)

libbip_a_SOURCES = \
	bip.c bip.h \
	bucket.c bucket.h \
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
libbip_a_LIBADD = libbiplex.a

bin_PROGRAMS = bip bipmkpw

bip_SOURCES = bip_main.c
bip_CFLAGS = $(OPENSSL_CFLAGS) $(AM_CFLAGS)
bip_LDADD = libbip.a libbiplex.a $(OPENSSL_LIBS)

bipmkpw_SOURCES = bipmkpw.c md5.c util.c
bipmkpw_CFLAGS = $(OPENSSL_CFLAGS) $(AM_CFLAGS)
bipmkpw_LDADD = libbip.a libbiplex.a $(OPENSSL_LIBS)

AM_YFLAGS= -d
BUILT_SOURCES = conf.c conf.h lex.c

AM_CFLAGS=-Wall -Wextra -Werror
