#include <check.h>
#include "../src/connection.h"
#include "../src/poller.h"
#include "../src/irc.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/errno.h>
#include <fcntl.h>

extern int sighup;
extern FILE *conf_global_log_file;
extern int conf_log_level;

extern void (*extra_callback_for_tests)(void *);
extern void *extra_callback_for_tests_data;

void init_test()
{
	conf_global_log_file = stderr;
	conf_log_level = LOG_DEBUGTOOMUCH + 1;
	signal(SIGPIPE, SIG_IGN);
}

struct irc_test_server;

typedef struct irc_test_server_client_state {
	connection_t *connection;
	int replay_line;
	array_t *replay_lines;
	struct irc_test_server *server;
} irc_test_server_client_state_t;

typedef struct irc_test_server {
	listener_t listener;
	array_t clients;
	array_t client_replay_lines;
	int num_expected_clients;
	int ssl;
} irc_test_server_t;

char *irc_test_server_client_state_current_line(
	irc_test_server_client_state_t *client_state)
{
	if (client_state->replay_line
	    >= array_count(client_state->replay_lines)) {
		return NULL;
	}
	return array_get(client_state->replay_lines, client_state->replay_line);
}

void irc_test_server_init(irc_test_server_t *server, int ssl)
{
	listener_ssl_options_t options;
	listener_ssl_options_init(&options);
	options.cert_pem_file = "bip.test.pem";
	array_init(&server->clients);
	listener_init(&server->listener, "127.0.0.1", 6667,
		      ssl ? &options : NULL);
	array_init(&server->client_replay_lines);
	server->ssl = ssl;
}

void irc_test_server_process(irc_test_server_t *server)
{
	connection_t *connection;
	while ((connection = list_remove_first(
			&server->listener.accepted_connections))) {
		irc_test_server_client_state_t *state =
			bip_malloc(sizeof(irc_test_server_client_state_t));
		connection->user_data = state;
		state->server = server;
		state->connection = connection;
		state->replay_line = 0;
		state->replay_lines = &server->client_replay_lines;
		array_push(&server->clients, state);
		log(LOG_ERROR, "IRC TEST SERVER, new client: %x", connection);
	}

	int i;
	for (i = 0; i < array_count(&server->clients); i++) {
		irc_test_server_client_state_t *client_state =
			array_get(&server->clients, i);
		if (client_state->connection->connected == CONN_INPROGRESS) {
			log(LOG_ERROR, "fd: %d, still connecting",
			    client_state->connection->handle);
			return;
		}
		if (client_state->connection->connected == CONN_SSL_CONNECT) {
			log(LOG_ERROR, "fd: %d, still establishing ssl things",
			    client_state->connection->handle);
			return;
		}
		ck_assert(cn_is_connected(client_state->connection));
		char *line =
			irc_test_server_client_state_current_line(client_state);
		if (line == NULL) {
			if (!list_is_empty(
				    client_state->connection->incoming_lines)) {
				char *actual_line = list_remove_first(
					client_state->connection
						->incoming_lines);
				log(LOG_DEBUG, "TEST SERVER got (spurious): %s",
				    actual_line);
				free(actual_line);
			}
			continue;
		}
		char *err_msg = bip_malloc(256);
		snprintf(err_msg, 255,
			 "Proxy->Server connection died before %s (%d)", line,
			 client_state->connection->connected);
		err_msg[255] = 0;
		ck_assert_msg(cn_is_connected(client_state->connection),
			      err_msg);
		free(err_msg);
		if (line[0] == 'S') {
			write_line(client_state->connection, line + 2);
			log(LOG_DEBUG, "TEST SERVER sent: %s", line + 2);
			client_state->replay_line++;
		} else if (line[0] == 'R') {
			if (!list_is_empty(
				    client_state->connection->incoming_lines)) {
				char *actual_line = list_remove_first(
					client_state->connection
						->incoming_lines);
				log(LOG_DEBUG, "TEST SERVER got: %s",
				    actual_line);
				ck_assert_str_eq(line + 2, actual_line);
				free(actual_line);
				client_state->replay_line++;
			}
		} else {
			fatal("Bad line format: %s", line);
		}
	}
}

typedef struct irc_test_client {
	connection_t *connection;
	array_t proxy_replay_lines;
	int proxy_replay_line;
} irc_test_client_t;

void irc_test_client_init(irc_test_client_t *client, int client_ssl)
{
	connection_ssl_options_t options;
	connection_ssl_options_init(&options);
	options.ssl_check_mode = SSL_CHECK_NONE;
	array_init(&client->proxy_replay_lines);
	client->proxy_replay_line = 0;
	client->connection = connection_new("127.0.0.1", 7777, NULL, 0,
					    client_ssl ? &options : NULL, 100);
}

char *irc_test_client_current_line(irc_test_client_t *client)
{
	if (client->proxy_replay_line
	    >= array_count(&client->proxy_replay_lines)) {
		return NULL;
	}
	return array_get(&client->proxy_replay_lines,
			 client->proxy_replay_line);
}

void irc_test_client_process(irc_test_client_t *client)
{
	if (client->proxy_replay_line
	    == array_count(&client->proxy_replay_lines)) {
		return;
	}
	if (client->connection->connected == CONN_INPROGRESS
	    || client->connection->connected == CONN_SSL_CONNECT) {
		return;
	}
	char *line = irc_test_client_current_line(client);
	if (line == NULL) {
		connection_close(client->connection);
		return;
	}
	ck_assert(cn_is_connected(client->connection));
	if (line[0] == 'S') {
		write_line(client->connection, line + 2);
		log(LOG_DEBUG, "TEST CLIENT SENT: %s", line + 2);
		client->proxy_replay_line++;
	} else if (line[0] == 'R') {
		descriptor_t *d = poller_get_descriptor(
			global_poller(), client->connection->handle);
		char *dbg = descriptor_dbg_string(d);
		log(LOG_DEBUG, "%s", dbg);
		free(dbg);
		if (!list_is_empty(client->connection->incoming_lines)) {
			char *actual_line = list_remove_first(
				client->connection->incoming_lines);
			log(LOG_DEBUG, "TEST CLIENT GOT: %s", actual_line);
			ck_assert_str_eq(line + 2, actual_line);
			free(actual_line);
			client->proxy_replay_line++;
		}
	}
}

void set_up_bip(bip_t *bip, int server_ssl, int client_ssl)
{
	struct network *n;
	n = bip_calloc(sizeof(struct network), 1);
	hash_insert(&bip->networks, "net0", n);
	n->ssl = server_ssl;
	n->serverv = bip_realloc(n->serverv, sizeof(struct server));
	n->serverc = 1;
	memset(&n->serverv[0], 0, sizeof(struct server));
	n->serverv[0].host = "127.0.0.1";
	n->serverv[0].port = 6667;

	struct bipuser *u;
	u = bip_calloc(sizeof(struct bipuser), 1);
	u->name = strdup("user0");
	u->default_nick = strdup("nick0");
	u->default_username = strdup("username0");
	u->default_realname = strdup("realname0");
	// tata
	hash_binary("10dda7edef3b7b946f659673e4e84e816a1fbc7e", &u->password,
		    &u->seed);

	hash_insert(&bip->users, "user0", u);
	hash_init(&u->connections, HASH_NOCASE);

	struct link *l;
	l = irc_link_new();
	l->name = strdup("connection0");
	hash_insert(&u->connections, "connection0", l);
	list_add_last(&bip->link_list, l);
	l->user = u;
	l->log = log_new(u, "log0");
	l->network = n;
}

void test_proxy_connects_opts(int server_ssl)
{
	bip_t bip;
	bip_init(&bip);
	bip.listener = listener_new("127.0.0.1", 7777, NULL);
	assert(bip.listener);

	irc_test_server_t server;
	irc_test_server_init(&server, server_ssl);
	server.num_expected_clients = 1;

	array_push(&server.client_replay_lines,
		   "R:USER username0 0 * realname0");
	array_push(&server.client_replay_lines, "R:NICK nick0");
	array_push(&server.client_replay_lines,
		   "S::servername 001 nick0 :Welcome nick0\r\n");
	array_push(&server.client_replay_lines,
		   "S::servername 376 nick0 :End of /MOTD command.\r\n");

	set_up_bip(&bip, server_ssl, /*client_ssl=*/0);
	ck_assert_int_eq(0, list_count(&bip.conn_list));
	bip_tick(&bip);
	ck_assert_int_eq(1, list_count(&bip.conn_list));
	while (array_count(&server.clients) != 1) {
		irc_test_server_process(&server);
		irc_one_shot(&bip, 10);
	}
	log(LOG_ERROR, "proxy connected to server");
	// Find the server link.
	ck_assert_int_eq(1, list_count(&bip.link_list));
	struct link *link = list_get_first(&bip.link_list);
	ck_assert(link != NULL);
	ck_assert(link->l_server != NULL);
	ck_assert_int_eq(link->s_state, IRCS_NONE);
	connection_t *bip_to_server = CONN(link->l_server);
	while (link->s_state != IRCS_CONNECTED) {
		irc_one_shot(&bip, 10);
		irc_test_server_process(&server);
	}
	ck_assert_int_eq(array_count(&server.clients), 1);
	irc_test_server_client_state_t *client_state =
		array_get(&server.clients, 0);
	ck_assert_int_eq(client_state->replay_line, 4);
}

START_TEST(test_proxy_connects)
{
	test_proxy_connects_opts(0);
}
END_TEST

#ifdef HAVE_LIBSSL
START_TEST(test_proxy_connects_ssl)
{
	test_proxy_connects_opts(1);
}
END_TEST
#endif

void test_proxy_and_client_connects_opt(int server_ssl, int client_ssl)
{
	bip_t bip;
	bip_init(&bip);
	if (client_ssl) {
		listener_ssl_options_t options;
		listener_ssl_options_init(&options);
		options.cert_pem_file = "bip.test.pem";
		bip.listener = listener_new("127.0.0.1", 7777, &options);
	} else {
		bip.listener = listener_new("127.0.0.1", 7777, NULL);
	}
	assert(bip.listener);

	irc_test_server_t server;
	irc_test_server_init(&server, server_ssl);
	server.num_expected_clients = 1;

	array_push(&server.client_replay_lines,
		   "R:USER username0 0 * realname0");
	array_push(&server.client_replay_lines, "R:NICK nick0");
	array_push(&server.client_replay_lines,
		   "S::servername 001 nick0 :Welcome nick0\r\n");
	array_push(&server.client_replay_lines,
		   "S::servername 376 nick0 :End of /MOTD command.\r\n");

	set_up_bip(&bip, server_ssl, client_ssl);
	ck_assert_int_eq(0, list_count(&bip.conn_list));
	bip_tick(&bip);
	ck_assert_int_eq(1, list_count(&bip.conn_list));
	while (array_count(&server.clients) != 1) {
		irc_test_server_process(&server);
		irc_one_shot(&bip, 10);
	}
	log(LOG_ERROR, "proxy connected to server");
	// Find the server link.
	ck_assert_int_eq(1, list_count(&bip.link_list));
	struct link *link = list_get_first(&bip.link_list);
	ck_assert(link != NULL);
	ck_assert(link->l_server != NULL);
	ck_assert_int_eq(link->s_state, IRCS_NONE);
	connection_t *bip_to_server = CONN(link->l_server);
	while (link->s_state != IRCS_CONNECTED) {
		irc_one_shot(&bip, 10);
		irc_test_server_process(&server);
	}
	ck_assert_int_eq(array_count(&server.clients), 1);
	irc_test_server_client_state_t *client_state =
		array_get(&server.clients, 0);
	ck_assert_int_eq(client_state->replay_line, 4);
	irc_test_client_t client;
	irc_test_client_init(&client, client_ssl);
	array_push(&client.proxy_replay_lines,
		   "S:USER username0 0 * realname0\r\n");
	array_push(&client.proxy_replay_lines, "S:NICK nick0\r\n");
	array_push(&client.proxy_replay_lines,
		   "R::b.i.p NOTICE nick0 :You should type /QUOTE PASS "
		   "your_username:your_password:your_connection_name");
	array_push(&client.proxy_replay_lines,
		   "S:PASS user0:tata:connection0\r\n");
	array_push(&client.proxy_replay_lines,
		   "R::servername 001 nick0 :Welcome nick0");
	array_push(&client.proxy_replay_lines,
		   "R::servername 376 nick0 :End of /MOTD command.");
	while (link->l_clientc == 0) {
		irc_one_shot(&bip, 10);
		irc_test_server_process(&server);
		irc_test_client_process(&client);
	}
	ck_assert_int_eq(client.proxy_replay_line, 4);
	while (client.proxy_replay_line != 6) {
		irc_one_shot(&bip, 10);
		irc_test_server_process(&server);
		irc_test_client_process(&client);
	}
}

START_TEST(test_proxy_and_client_connects)
{
	test_proxy_and_client_connects_opt(0, 0);
}
END_TEST

#ifdef HAVE_LIBSSL

START_TEST(test_proxy_and_client_connects_ssl)
{
	test_proxy_and_client_connects_opt(1, 1);
}
END_TEST

#if 0
// to run with CK_DEFAULT_TIMEOUT=10000
START_TEST(test_the_test) {
	irc_test_server_t server;
	irc_test_server_init(&server, 1);
	server.num_expected_clients = 1;
	array_push(&server.client_replay_lines,
		   "R:USER username0 0 * realname0");
	array_push(&server.client_replay_lines, "R:NICK nick0");
	array_push(&server.client_replay_lines,
		   "S::servername 001 nick0 :Welcome nick0\r\n");
	array_push(&server.client_replay_lines,
		   "S::servername 376 end :End of /MOTD command.\r\n");
	for (;;) {
		log(LOG_DEBUG, "INLOOP");
		irc_test_server_process(&server);
		poller_wait(global_poller(), 100);
	}
	log(LOG_DEBUG, "HUH?");
}
END_TEST
#endif

#endif

Suite *money_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("bip");
	tc_core = tcase_create("irc");

	tcase_add_test(tc_core, test_proxy_connects);
	tcase_add_test(tc_core, test_proxy_and_client_connects);
#ifdef HAVE_LIBSSL
	tcase_add_test(tc_core, test_proxy_connects_ssl);
	tcase_add_test(tc_core, test_proxy_and_client_connects_ssl);
#endif
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	init_test();

	s = money_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
