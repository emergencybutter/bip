if COND_WANT_TESTS
  MAYBE_TESTS = tests
endif
SUBDIRS = src . $(MAYBE_TESTS)

dist_man_MANS = bip.1 bip.conf.5 bipmkpw.1

examplesdir = $(prefix)/share/doc/bip/examples/
dist_examples_DATA = samples/bip.conf samples/bip.vim

EXTRA_DIST = \
	BUGS \
	scripts/bip-release \
	scripts/bipgenconfig \
	systemd
