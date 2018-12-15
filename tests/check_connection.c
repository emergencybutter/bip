#include <check.h>
#include "../src/connection.h"
#include "../src/poller.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/errno.h>
#include <fcntl.h>

extern FILE *conf_global_log_file;
extern int conf_log_level;

START_TEST(test_connection_basic)
{
	conf_global_log_file = stderr;
	conf_log_level = LOG_DEBUGTOOMUCH + 1;
	listener_t *server =
		listener_new("localhost", 6777, /*listener_ssl_options=*/NULL);
	int msec = 100;
	mylog(LOG_DEBUG, "wait");

	poller_wait(global_poller(), msec);
	ck_assert(list_is_empty(&server->accepted_connections));

	connection_t *client =
		connection_new("localhost", 6777, NULL, 0, NULL, 100);

	ck_assert_int_eq(client->connected, CONN_INPROGRESS);
	poller_wait(global_poller(), msec);
	while (list_is_empty(&server->accepted_connections)) {
		poller_wait(global_poller(), msec);
	}
	ck_assert(!list_is_empty(&server->accepted_connections));
	connection_t *receiving_end =
		list_remove_first(&server->accepted_connections);
	ck_assert_int_eq(client->connected, CONN_OK);
	ck_assert_int_eq(receiving_end->connected, CONN_INPROGRESS);
	poller_wait(global_poller(), msec);
	ck_assert_int_eq(receiving_end->connected, CONN_OK);
	connection_close(client);
	connection_close(receiving_end);
	poller_wait(global_poller(), msec);
}
END_TEST

#ifdef HAVE_LIBSSL
START_TEST(test_connection_ssl)
{
	connection_ssl_initialize();

	conf_global_log_file = stderr;
	conf_log_level = LOG_DEBUGTOOMUCH + 1;

	listener_ssl_options_t listener_options;
	listener_ssl_options_init(&listener_options);
	listener_options.cert_pem_file = "bip.test.pem";
	listener_t *server = listener_new("127.0.0.1", 6667, &listener_options);

	connection_ssl_options_t connection_options;
	connection_ssl_options_init(&connection_options);
	connection_options.ssl_check_mode = SSL_CHECK_NONE;

	mylog(LOG_DEBUG, "wait");
	poller_wait(global_poller(), 0);
	ck_assert(list_is_empty(&server->accepted_connections));

	connection_t *client = connection_new("127.0.0.1", 6667, NULL, 0,
					      &connection_options, 100);
	ck_assert_int_eq(client->connected, CONN_INPROGRESS);
	while (client->connected == CONN_INPROGRESS) {
		poller_wait(global_poller(), 0);
	}
	while (list_is_empty(&server->accepted_connections)) {
		poller_wait(global_poller(), 0);
	}
	connection_t *receiving_end =
		list_remove_first(&server->accepted_connections);
	while (client->connected != CONN_OK) {
		poller_wait(global_poller(), 0);
	}
	while (receiving_end->connected != CONN_OK) {
		poller_wait(global_poller(), 0);
	}
	connection_close(client);
	connection_close(receiving_end);
	poller_wait(global_poller(), 0);
}
END_TEST
#endif

Suite *money_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("bip");

	tc_core = tcase_create("connection");

	tcase_add_test(tc_core, test_connection_basic);
#ifdef HAVE_LIBSSL
	tcase_add_test(tc_core, test_connection_ssl);
#endif
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
