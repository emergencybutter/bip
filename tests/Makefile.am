if DEBUG
AM_CFLAGS = -g3 -O0
else
AM_CFLAGS = -O2
endif


TESTS = check_poller check_line check_connection check_irc
check_PROGRAMS = check_poller check_line check_connection check_irc

check_line_SOURCES = check_line.c $(top_builddir)/src/line.h
check_line_CFLAGS = @CHECK_CFLAGS@ $(OPENSSL_CFLAGS)
check_line_LDADD = $(top_builddir)/src/libbip.a @CHECK_LIBS@ $(OPENSSL_LIBS)

check_poller_SOURCES = check_poller.c $(top_builddir)/src/poller.h
check_poller_CFLAGS = @CHECK_CFLAGS@ $(OPENSSL_CFLAGS)
check_poller_LDADD = $(top_builddir)/src/libbip.a @CHECK_LIBS@ $(OPENSSL_LIBS)

check_connection_SOURCES = check_connection.c $(top_builddir)/src/connection.h
check_connection_CFLAGS = @CHECK_CFLAGS@ $(OPENSSL_CFLAGS)
check_connection_LDADD = $(top_builddir)/src/libbip.a @CHECK_LIBS@ $(OPENSSL_LIBS)

check_irc_SOURCES = check_irc.c $(top_builddir)/src/irc.h
check_irc_CFLAGS = @CHECK_CFLAGS@ $(OPENSSL_CFLAGS)
check_irc_LDADD = $(top_builddir)/src/libbip.a @CHECK_LIBS@ $(OPENSSL_LIBS)
