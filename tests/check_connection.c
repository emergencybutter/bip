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
    list_t *connection_list = list_new(list_ptr_cmp);
    listener_t* server = listener_new("localhost", 6777, /*listener_ssl_options=*/NULL);
    list_add_last(connection_list, server);
    int msec = 100;
	mylog(LOG_DEBUG, "wait");

	poller_wait(global_poller(), msec);
    ck_assert(list_is_empty(&server->accepted_connections));

    connection_t *client = connection_new("localhost", 6777, NULL, 0, NULL, 100);
	mylog(LOG_DEBUG, "client: %d", client->handle);

    list_add_last(connection_list, client);
    ck_assert_int_eq(client->connected, CONN_INPROGRESS);
    mylog(LOG_DEBUG, "wait1");
    poller_wait(global_poller(), msec);
    ck_assert(!list_is_empty(&server->accepted_connections));
    connection_t* receiving_end = list_remove_first(&server->accepted_connections);
	mylog(LOG_DEBUG, "receiving client: %d", receiving_end->handle);
    ck_assert_int_eq(client->connected, CONN_OK);
	ck_assert_int_eq(receiving_end->connected, CONN_INPROGRESS);
	poller_wait(global_poller(), msec);
	ck_assert_int_eq(receiving_end->connected, CONN_OK);
    connection_close(client);
	connection_close(receiving_end);
}
END_TEST

START_TEST(test_connection_ssl)
{
	connection_ssl_initialize();

	conf_global_log_file = stderr;
	conf_log_level = LOG_DEBUGTOOMUCH + 1;
	list_t *connection_list = list_new(list_ptr_cmp);

	listener_ssl_options_t listener_options;
	listener_ssl_options_init(&listener_options);
	listener_options.cert_pem_file = "bip.test.pem";
	listener_t *server = listener_new("localhost", 6777, &listener_options);

	connection_ssl_options_t connection_options;
	connection_ssl_options_init(&connection_options);
	connection_options.ssl_check_mode = SSL_CHECK_NONE;


	list_add_last(connection_list, server);
	int msec = 100;
	mylog(LOG_DEBUG, "wait");

	poller_wait(global_poller(), msec);
	ck_assert(list_is_empty(&server->accepted_connections));

	connection_t *client = connection_new("localhost", 6777, NULL, 0,
					      &connection_options, 100);
	mylog(LOG_DEBUG, "client: %d", client->handle);

	list_add_last(connection_list, client);
	ck_assert_int_eq(client->connected, CONN_INPROGRESS);
	mylog(LOG_DEBUG, "wait1");
	poller_wait(global_poller(), msec);
	ck_assert(!list_is_empty(&server->accepted_connections));
	connection_t *receiving_end =
		list_remove_first(&server->accepted_connections);
	mylog(LOG_DEBUG, "receiving client: %d", receiving_end->handle);
	ck_assert_int_eq(client->connected, CONN_SSL_CONNECT);
	ck_assert_int_eq(receiving_end->connected, CONN_INPROGRESS);
	poller_wait(global_poller(), msec);
	ck_assert_int_eq(receiving_end->connected, CONN_OK);
	connection_close(client);
	connection_close(receiving_end);
}
END_TEST

Suite *money_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("bip");

	tc_core = tcase_create("connection");

	tcase_add_test(tc_core, test_connection_basic);
	tcase_add_test(tc_core, test_connection_ssl);
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
