#include <check.h>
#include "../src/poller.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/errno.h>
#include <fcntl.h>

void poller_pipe(int *filedes)
{
	int error = pipe(filedes);
	if (error == -1) {
		fatal("pipe: %s", strerror(errno));
	}
	error = fcntl(filedes[0], F_SETFL, O_NONBLOCK);
	if (error < 0) {
		fatal("fcntl: %s", strerror(error));
	}
	error = fcntl(filedes[1], F_SETFL, O_NONBLOCK);
	if (error < 0) {
		fatal("fcntl: %s", strerror(error));
	}
}

void inc_pointee(void *p)
{
	int *ip = p;
	printf("incrementing %d\n", *ip);
	(*ip)++;
}

void should_not_call(void *_)
{
	fatal("Called should_not_call\n");
}

START_TEST(test_poller_basic)
{
	int f1[2];
	poller_pipe(f1);

	poller_t *poller = poller_create();
	descriptor_t *d1_read = poller_register(poller, f1[0]);
	descriptor_t *d1_write = poller_register(poller, f1[1]);
	int an_integer = 0;
	d1_read->on_in = &inc_pointee;
	d1_read->on_out = &should_not_call;
	d1_read->on_hup = &should_not_call;
	d1_read->data = &an_integer;

	d1_write->on_in = &should_not_call;
	d1_write->on_out = &inc_pointee;
	d1_write->on_hup = &should_not_call;
	d1_write->data = &an_integer;

	// Nothing to read.
	poller_wait(poller, 0);
	ck_assert_int_eq(an_integer, 0);

	// Something to read, but set_events not called.
	int n = write(f1[1], "a", 1);
	ck_assert_int_eq(n, 1);
	poller_wait(poller, 0);
	ck_assert_int_eq(an_integer, 0);

	// Calling set_events, should call on_in();
	descriptor_set_events(d1_read, POLLER_IN);
	poller_wait(poller, 0);
	ck_assert_int_eq(an_integer, 1);

	// Should call on_in one more time, we haven't read anything.
	poller_wait(poller, 0);
	ck_assert_int_eq(an_integer, 2);

	// Now read the byte on the wire.
	char buf[1];
	n = read(f1[0], buf, 1);
	ck_assert_int_eq(n, 1);
	// Nothing to read any more.
	poller_wait(poller, 0);
	ck_assert_int_eq(an_integer, 2);

	// Add something back on the pipe, but listen for "out"
	n = write(f1[1], "a", 1);
	ck_assert_int_eq(n, 1);
	descriptor_set_events(d1_read, POLLER_OUT);
	descriptor_unset_events(d1_read, POLLER_IN);
	poller_wait(poller, 0);
	ck_assert_int_eq(an_integer, 2);

	// Listen for out, on the write fd.
	descriptor_set_events(d1_write, POLLER_OUT);
	poller_wait(poller, 0);
	ck_assert_int_eq(an_integer, 3);

	// Fill up the pipe so we can't write anymore.
	char buffer[4096];
	n = write(f1[1], buffer, 4096);
	while (n > 0) {
		n = write(f1[1], buffer, 4096);
	}
	poller_wait(poller, 0);
	ck_assert_int_eq(an_integer, 3);

	// drain the read end.
	n = read(f1[0], buffer, 4096);
	while (n > 0) {
		n = read(f1[0], buffer, 4096);
	}

	descriptor_unset_events(d1_write, POLLER_OUT);
	descriptor_set_events(d1_read, POLLER_HUP);
	descriptor_set_events(d1_read, POLLER_IN);
	d1_read->on_in = &inc_pointee;
	d1_read->on_hup = &inc_pointee;

	poller_wait(poller, 0);
	ck_assert_int_eq(an_integer, 3);

	int err = close(f1[1]);
	if (err < 0) {
		fatal("close: %s\n", strerror(errno));
	}
	poller_unregister(poller, f1[1]);
	poller_wait(poller, 0);
	ck_assert_int_eq(an_integer, 4);
}
END_TEST


Suite *money_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("bip");

	tc_core = tcase_create("poller");

	tcase_add_test(tc_core, test_poller_basic);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = money_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
