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
extern int default_items_per_sec;

void init_test()
{
	conf_global_log_file = stderr;
	conf_log_level = LOG_DEBUGTOOMUCH + 1;
	signal(SIGPIPE, SIG_IGN);
	// Get the anti flood out of the way.
	default_items_per_sec = 1000000;
}

struct irc_test_server;

typedef struct irc_test_server_connection {
	connection_t *connection;
	struct irc_test_server *server;
} irc_test_server_connection_t;

typedef struct irc_test_server {
	listener_t listener;
	array_t clients;
	int ssl;
} irc_test_server_t;

void irc_test_server_init(irc_test_server_t *server, int ssl)
{
	listener_ssl_options_t options;
	listener_ssl_options_init(&options);
	options.cert_pem_file = "bip.test.pem";
	array_init(&server->clients);
	listener_init(&server->listener, "127.0.0.1", 6667,
		      ssl ? &options : NULL);
	server->ssl = ssl;
}

void irc_test_server_wait_for_connection(irc_test_server_t *server, bip_t *bip)
{
	while (list_count(&server->listener.accepted_connections) == 0) {
		bip_tick(bip);
		irc_one_shot(bip, 10);
	}
}

irc_test_server_connection_t *
irc_test_server_connection(irc_test_server_t *server)
{
	connection_t *connection =
		list_remove_first(&server->listener.accepted_connections);
	irc_test_server_connection_t *state =
		bip_malloc(sizeof(irc_test_server_connection_t));
	connection->user_data = state;
	state->server = server;
	state->connection = connection;
	array_push(&server->clients, state);
	log(LOG_ERROR, "IRC TEST SERVER, new client: %x, fd: %d", connection,
	    connection->handle);
	return state;
}

int irc_test_server_connection_state(irc_test_server_connection_t *itsc)
{
	return itsc->connection->connected;
}

char *irc_test_server_connection_pop_line(irc_test_server_connection_t *itsc)
{
	return list_remove_first(itsc->connection->incoming_lines);
}

void irc_test_server_connection_write(irc_test_server_connection_t *itsc,
				      char *line)
{
	write_line(itsc->connection, line);
}

typedef struct irc_test_client {
	connection_t *connection;
} irc_test_client_t;

void irc_test_client_init(irc_test_client_t *client, int client_ssl)
{
	connection_ssl_options_t options;
	connection_ssl_options_init(&options);
	options.ssl_check_mode = SSL_CHECK_NONE;
	client->connection = connection_new("127.0.0.1", 7777, NULL, 0,
					    client_ssl ? &options : NULL, 100);
}

char *irc_test_client_current_line(irc_test_client_t *client)
{
	return list_remove_first(client->connection->incoming_lines);
}

struct link *set_up_bip(bip_t *bip, int server_ssl, int client_ssl)
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
	char *tmp = strdup("/tmp/check_irc_XXXXXX");
	u->ssl_check_store = mktemp(tmp);
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
	assert(l->untrusted_certs != NULL);
	return l;
}

void irc_test_server_connection_wait_for(irc_test_server_connection_t *server,
					 bip_t *bip, char *str)
{
	char *last_line = list_get_first(server->connection->incoming_lines);
	while (last_line == NULL || strcmp(last_line, str) != 0) {
		bip_tick(bip);
		irc_one_shot(bip, 100);
		last_line = list_get_first(server->connection->incoming_lines);
	}
	list_remove_first(server->connection->incoming_lines);
}

void irc_test_server_connection_write_line(irc_test_server_connection_t *itsc,
					   char *line)
{
	char *full_line = bip_malloc(strlen(line) + 3);
	memcpy(full_line, line, strlen(line) + 1);
	strcat(full_line, "\r\n");
	write_line(itsc->connection, full_line);
	free(full_line);
}

void irc_test_client_write_line(irc_test_client_t *client, char *line)
{
	char *full_line = bip_malloc(strlen(line) + 3);
	memcpy(full_line, line, strlen(line) + 1);
	strcat(full_line, "\r\n");
	write_line(client->connection, full_line);
	free(full_line);
}

void irc_test_client_wait_connected(irc_test_client_t *client, bip_t *bip)
{
	int state = client->connection->connected;
	while (client->connection->connected != CONN_OK) {
		if (state != client->connection->connected) {
			log(LOG_WARN, "connection state changed: %d -> %d",
			    state, client->connection->connected);
			state = client->connection->connected;
		}
		irc_one_shot(bip, 100);
		bip_tick(bip);
	}
}

void irc_test_client_wait_for(irc_test_client_t *client, bip_t *bip, char *str)
{
	char *last_line = list_get_first(client->connection->incoming_lines);
	log(LOG_WARN, "%s %s", last_line, str);
	while (last_line == NULL || strcmp(last_line, str) != 0) {
		bip_tick(bip);
		irc_one_shot(bip, 100);
		connection_tick(client->connection);
		last_line = list_get_first(client->connection->incoming_lines);
		log(LOG_WARN, "%s %s", last_line, str);
	}
	list_remove_first(client->connection->incoming_lines);
}

void test_proxy_connects_opts(int server_ssl)
{
	bip_t bip;
	bip_init(&bip);
	bip.listener = listener_new("127.0.0.1", 7777, NULL);
	assert(bip.listener);
	set_up_bip(&bip, server_ssl, /*client_ssl=*/0);

	irc_test_server_t server;
	irc_test_server_init(&server, server_ssl);

	irc_test_server_wait_for_connection(&server, &bip);

	irc_test_server_connection_t *server_connection =
		irc_test_server_connection(&server);

	irc_test_server_connection_wait_for(server_connection, &bip,
					    "USER username0 0 * realname0");

	irc_test_server_connection_wait_for(server_connection, &bip,
					    "NICK nick0");
	irc_test_server_connection_write_line(
		server_connection, ":servername 001 nick0 :Welcome nick0");
	irc_test_server_connection_write_line(
		server_connection,
		":servername 376 nick0 :End of /MOTD command.");

	ck_assert_int_eq(1, list_count(&bip.conn_list));
	ck_assert_int_eq(1, list_count(&bip.link_list));
	struct link *link = list_get_first(&bip.link_list);
	ck_assert(link != NULL);
	ck_assert(link->l_server != NULL);
	ck_assert_int_eq(link->s_state, IRCS_NONE);
	connection_t *bip_to_server = CONN(link->l_server);
	while (link->s_state != IRCS_CONNECTED) {
		irc_one_shot(&bip, 10);
		bip_tick(&bip);
	}
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

	set_up_bip(&bip, server_ssl, client_ssl);

	irc_test_server_t server;
	irc_test_server_init(&server, server_ssl);

	irc_test_server_wait_for_connection(&server, &bip);

	irc_test_server_connection_t *server_connection =
		irc_test_server_connection(&server);

	irc_test_server_connection_wait_for(server_connection, &bip,
					    "USER username0 0 * realname0");
	irc_test_server_connection_wait_for(server_connection, &bip,
					    "NICK nick0");
	irc_test_server_connection_write_line(
		server_connection, ":servername 001 nick0 :Welcome nick0");
	irc_test_server_connection_write_line(
		server_connection,
		":servername 376 nick0 :End of /MOTD command.");

	ck_assert_int_eq(1, list_count(&bip.conn_list));
	ck_assert_int_eq(1, list_count(&bip.link_list));
	struct link *link = list_get_first(&bip.link_list);
	ck_assert(link != NULL);
	ck_assert(link->l_server != NULL);
	ck_assert_int_eq(link->s_state, IRCS_NONE);
	connection_t *bip_to_server = CONN(link->l_server);
	while (link->s_state != IRCS_CONNECTED) {
		irc_one_shot(&bip, 10);
		bip_tick(&bip);
	}
	ck_assert_int_eq(array_count(&server.clients), 1);

	irc_test_client_t client;
	irc_test_client_init(&client, client_ssl);
	log(LOG_INFO, "Client: fd: %d", client.connection->handle);

	irc_test_client_wait_connected(&client, &bip);

	irc_test_client_write_line(&client, "USER username0 0 * realname0");
	irc_test_client_write_line(&client, "NICK nick0");
	irc_test_client_wait_for(
		&client, &bip,
		":b.i.p NOTICE nick0 :You should type /QUOTE PASS "
		"your_username:your_password:your_connection_name");
	irc_test_client_write_line(&client, "PASS user0:tata:connection0");
	irc_test_client_wait_for(&client, &bip,
				 ":servername 001 nick0 :Welcome nick0");
	irc_test_client_wait_for(
		&client, &bip, ":servername 376 nick0 :End of /MOTD command.");

	ck_assert(link != NULL);
	ck_assert_int_eq(link->l_clientc, 1);
	ck_assert_int_eq(CONN(link->l_clientv[0])->connected, CONN_OK);
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

START_TEST(test_adm_trust)
{
	bip_t bip;
	bip_init(&bip);
	bip.listener = listener_new("127.0.0.1", 7777, NULL);

	struct link *l = set_up_bip(&bip, /*server_ssl=*/1, /*client_ssl=*/0);
	l->ssl_check_mode = SSL_CHECK_BASIC;
	ck_assert_int_eq(0, list_count(&bip.conn_list));

	irc_test_server_t server;
	irc_test_server_init(&server, /*server_ssl=*/1);

	// Find the server link.
	ck_assert_int_eq(1, list_count(&bip.link_list));

	struct link *link = list_get_first(&bip.link_list);
	ck_assert(link != NULL);
	ck_assert(link->l_server == NULL);
	ck_assert_int_eq(link->s_state, IRCS_NONE);

	connection_t *bip_to_server = CONN(link->l_server);
	// Wait for a connection failure.
	while (sk_X509_num(link->untrusted_certs) == 0) {
		irc_one_shot(&bip, 10);
		bip_tick(&bip);
		log(LOG_INFO, "Untrusted certs: %d",
		    sk_X509_num(link->untrusted_certs));
	}

	// TODO Reproduce a bug where disconnecting clients while waiting for
	// adm trust cause segv.
	irc_test_client_t client;
	irc_test_client_init(&client, /*client_ssl=*/0);
	log(LOG_INFO, "Client: fd: %d", client.connection->handle);

	irc_test_client_wait_connected(&client, &bip);

	irc_test_client_write_line(&client, "USER username0 0 * realname0");
	irc_test_client_write_line(&client, "NICK nick0");
	irc_test_client_wait_for(
		&client, &bip,
		":b.i.p NOTICE nick0 :You should type /QUOTE PASS "
		"your_username:your_password:your_connection_name");
	irc_test_client_write_line(&client, "PASS user0:tata:connection0");
	irc_test_client_wait_for(
		&client, &bip,
		":b.i.p NOTICE TrustEm :This server SSL certificate was "
		"not accepted because it is not in your store of trusted "
		"certificates:");
	irc_test_client_wait_for(&client, &bip,
				 ":b.i.p NOTICE TrustEm :Subject: /C=US/O=Sexy "
				 "boys/OU=Bip/CN=Bip");
	irc_test_client_wait_for(&client, &bip,
				 ":b.i.p NOTICE TrustEm :Issuer:  /C=US/O=Sexy "
				 "boys/OU=Bip/CN=Bip");
	irc_test_client_wait_for(
		&client, &bip,
		":b.i.p NOTICE TrustEm :MD5 fingerprint: "
		"C7:BB:C7:85:51:3A:B9:74:41:28:EF:82:1B:FA:5C:6A");
	irc_test_client_wait_for(
		&client, &bip,
		":b.i.p NOTICE TrustEm :WARNING: if you've already "
		"trusted a certificate for this server before, that "
		"probably means it has changed.");
	irc_test_client_wait_for(
		&client, &bip,
		":b.i.p NOTICE TrustEm :If so, YOU MAY BE SUBJECT OF A "
		"MAN-IN-THE-MIDDLE ATTACK! PLEASE DON'T TRUST THIS "
		"CERTIFICATE IF YOU'RE NOT SURE THIS IS NOT THE CASE.");
	irc_test_client_wait_for(
		&client, &bip,
		":b.i.p NOTICE TrustEm :Type /QUOTE BIP TRUST OK to trust "
		"this certificate, /QUOTE BIP TRUST NO to discard it.");
	irc_test_client_write_line(&client, "BIP TRUST OK");
	irc_test_client_wait_for(
		&client, &bip,
		":irc.bip.net NOTICE pouet :If the certificate is "
		"trusted, bip should be able to connect to the server on "
		"the next retry. Please wait a while and try connecting "
		"your client again.");

	ck_assert_int_eq(1, list_count(&bip.connecting_client_list));
	struct link_client *ic = list_get_first(&bip.connecting_client_list);
	connection_t *proxy_connecting_client_conn = CONN(ic);

	ck_assert_int_eq(TYPE(ic), IRC_TYPE_TRUST_CLIENT);
}
END_TEST

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
	tcase_add_test(tc_core, test_adm_trust);
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
