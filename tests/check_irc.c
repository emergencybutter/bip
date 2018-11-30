#include <check.h>
#include "../src/connection.h"
#include "../src/poller.h"
#include "../src/irc.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <pthread.h>

extern int sighup;
extern FILE *conf_global_log_file;
extern int conf_log_level;

void init_test()
{
	conf_global_log_file = stderr;
	conf_log_level = LOG_DEBUGTOOMUCH + 1;
	signal(SIGPIPE, SIG_IGN);
}

pthread_mutex_t server_state_mutex;
char *server_state = "init";
int server_fd;
list_t server_expected_lines;

void set_server_state(char *state)
{
	pthread_mutex_lock(&server_state_mutex);
	server_state = state;
	pthread_mutex_unlock(&server_state_mutex);
}

int is_server_state(char *state)
{
	int ret;
	pthread_mutex_lock(&server_state_mutex);
	ret = strcmp(state, server_state);
	pthread_mutex_unlock(&server_state_mutex);
	return ret;
}

void server_add_expected_line(char *str)
{
	pthread_mutex_lock(&server_state_mutex);
	list_add_last(&server_expected_lines, str);
	pthread_mutex_unlock(&server_state_mutex);
}

char *server_pop_expected_line()
{
	char *str;
	pthread_mutex_lock(&server_state_mutex);
	if (list_is_empty(&server_expected_lines)) {
		return NULL;
	}
	str = list_remove_first(&server_expected_lines);
	pthread_mutex_unlock(&server_state_mutex);
	return str;
}

char *read_line(int fd)
{
	int size = 256;
	char *line = malloc(size + 1);
	int index = 0;
	do {
		int ret = read(fd, line + index, 1);
		line[index + 1] = 0;
		ck_assert_int_eq(ret, 1);
		index++;
		if (index == size) {
			size *= 2;
			line = realloc(line, size + 1);
		}
	} while (line[index - 1] != '\n');
	line[index] = 0;
	return line;
}

void *irc_server(void *unused)
{
	(void)unused;

	int err;
	struct addrinfo *res;
	struct addrinfo hint = {.ai_flags = AI_PASSIVE,
				.ai_family = AF_UNSPEC,
				.ai_socktype = SOCK_STREAM,
				.ai_protocol = 0,

				.ai_addrlen = 0,
				.ai_addr = 0,
				.ai_canonname = 0,
				.ai_next = 0};

	err = getaddrinfo("127.0.0.1", "6667", &hint, &res);
	if (err) {
		fatal("getaddrinfo(): %s", gai_strerror(err));
	}

	int listener_fd;
	if ((listener_fd =
		     socket(res->ai_family, res->ai_socktype, res->ai_protocol))
	    < 0) {
		fatal("socket(): %s", gai_strerror(err));
	}

	int opt = 1;
	if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int))
	    < 0) {
		fatal("setsockopt(SO_REUSEADDR):%s", strerror(errno));
	}

	if (bind(listener_fd, res->ai_addr, res->ai_addrlen) < 0) {
		fatal("bind(): %s", strerror(errno));
	}

	err = listen(listener_fd, 256);
	if (err == -1) {
		fatal("listen(): %s", strerror(errno));
	}

	set_server_state("accepting");

	struct sockaddr addr;
	socklen_t addrlen;
	server_fd = accept(listener_fd, &addr, &addrlen);
	if (server_fd == -1) {
		fatal("accept(): %s", strerror(errno));
	}
	set_server_state("accepted");

	err = getaddrinfo("127.0.0.1", "7777", &hint, &res);
	if (err) {
		fatal("getaddrinfo(): %s", gai_strerror(err));
	}

	int client_fd;
	if ((client_fd =
		     socket(res->ai_family, res->ai_socktype, res->ai_protocol))
	    < 0) {
		fatal("socket(): %s", gai_strerror(err));
	}

	if (connect(client_fd, res->ai_addr, res->ai_addrlen) < 0) {
		fatal("connect(): %s", strerror(errno));
	}

	char *expected;
	while (expected = server_pop_expected_line()) {
		if (expected[0] == 'S') {
			if (expected[1] == 'R') {
				log(LOG_DEBUG, "Receiving %s", expected + 3);
				char *line = read_line(server_fd);
				log(LOG_DEBUG, "read (server): %s", line);
				ck_assert_str_eq(line, expected + 3);
				free(line);
			} else if (expected[1] == 'S') {
				log(LOG_DEBUG, "Sending %s", expected + 3);
				size_t size = strlen(expected + 3);
				ck_assert_int_eq(
					write(server_fd, expected + 3, size),
					size);
			}
		} else if (expected[0] == 'C') {
			if (expected[1] == 'R') {
				log(LOG_DEBUG, "Expecting (client-side) %s",
				      expected + 3);
				char *line = read_line(client_fd);
				ck_assert_str_eq(line, expected + 3);
				free(line);
			} else if (expected[1] == 'S') {
				log(LOG_DEBUG, "Client Sending %s",
				      expected + 3);
				size_t size = strlen(expected + 3);
				ck_assert_int_eq(
					write(client_fd, expected + 3, size),
					size);
			}
		}
	}

	close(server_fd);
	close(listener_fd);

	// Make the tests thread quit irc_main.
	sighup = 1;
	return NULL;
}

START_TEST(test_irc_basic)
{
	list_init(&server_expected_lines, list_ptr_cmp);
	list_add_last(&server_expected_lines,
		      "SR:USER username0 0 * realname0\r\n");
	list_add_last(&server_expected_lines, "SR:NICK nick0\r\n");
	list_add_last(&server_expected_lines,
		      "SS:leguin.freenode.net 001 nick0 :Welcome to the "
		      "freenode Internet Relay Chat Network nick0\r\n");
	list_add_last(&server_expected_lines,
		      "SS::leguin.freenode.net 376 lsajfds :End of /MOTD "
		      "command.\r\n");
	list_add_last(&server_expected_lines, "CS:USER a b c d\r\n");
	list_add_last(&server_expected_lines, "CS:NICK d\r\n");
	list_add_last(&server_expected_lines,
		      "CS:PASS user0:tata:connection0\r\n");
	pthread_mutex_init(&server_state_mutex, NULL);

	pthread_t thread;
	pthread_attr_t pthread_attr;
	pthread_attr_init(&pthread_attr);
	assert(pthread_create(&thread, &pthread_attr, &irc_server, NULL) == 0);
	pthread_attr_destroy(&pthread_attr);

	for (;;) {
		if (is_server_state("accepting") == 0) {
			break;
		}
	}
	bip_t bip;
	bip_init(&bip);
	bip.listener = listener_new("127.0.0.1", 7777, NULL);
	assert(bip.listener);

	struct network *n;
	n = bip_calloc(sizeof(struct network), 1);
	hash_insert(&bip.networks, "net0", n);
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

	hash_insert(&bip.users, "user0", u);
	hash_init(&u->connections, HASH_NOCASE);

	struct link *l;
	l = irc_link_new();
	l->name = strdup("link0");
	hash_insert(&u->connections, "connection0", l);
	list_add_last(&bip.link_list, l);
	l->user = u;
	l->log = log_new(u, "log0");
	l->network = n;
	irc_main(&bip);

	void *retval;
	assert(pthread_join(thread, &retval) == 0);
}
END_TEST

Suite *money_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("bip");
	tc_core = tcase_create("irc");

	tcase_add_test(tc_core, test_irc_basic);
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
