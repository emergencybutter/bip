TESTS = check_poller check_line check_connection check_irc check_bucket
check_PROGRAMS = check_poller check_line check_connection check_irc check_bucket

TESTS_LDADD = $(top_builddir)/src/libbip.a \
	      $(top_builddir)/src/libbiplex.a \
	      @CHECK_LIBS@ \
	      $(OPENSSL_LIBS)

check_line_SOURCES = check_line.c $(top_builddir)/src/line.h
check_line_CFLAGS = @CHECK_CFLAGS@ $(OPENSSL_CFLAGS)
check_line_LDADD = $(TESTS_LDADD)

check_poller_SOURCES = check_poller.c $(top_builddir)/src/poller.h
check_poller_CFLAGS = @CHECK_CFLAGS@ $(OPENSSL_CFLAGS)
check_poller_LDADD = $(TESTS_LDADD)

check_connection_SOURCES = check_connection.c $(top_builddir)/src/connection.h
check_connection_CFLAGS = @CHECK_CFLAGS@ $(OPENSSL_CFLAGS)
check_connection_LDADD = $(TESTS_LDADD)

check_irc_SOURCES = check_irc.c $(top_builddir)/src/irc.h
check_irc_CFLAGS = @CHECK_CFLAGS@ $(OPENSSL_CFLAGS)
check_irc_LDADD = $(TESTS_LDADD)

check_bucket_SOURCES = check_bucket.c $(top_builddir)/src/bucket.h
check_bucket_CFLAGS = @CHECK_CFLAGS@ $(OPENSSL_CFLAGS)
check_bucket_LDADD = $(TESTS_LDADD)
