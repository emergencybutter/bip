TESTS = check_poller check_line
check_PROGRAMS = check_poller check_line
check_poller_SOURCES = check_poller.c $(top_builddir)/src/poller.h
check_poller_CFLAGS = @CHECK_CFLAGS@
check_poller_LDADD = $(top_builddir)/src/libbip.a @CHECK_LIBS@

check_line_SOURCES = check_line.c $(top_builddir)/src/line.h
check_line_CFLAGS = @CHECK_CFLAGS@
check_line_LDADD = $(top_builddir)/src/libbip.a @CHECK_LIBS@
