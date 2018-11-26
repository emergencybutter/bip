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

void init_test() {
    conf_global_log_file = stderr;
    conf_log_level = LOG_DEBUGTOOMUCH + 1;
	signal(SIGPIPE, SIG_IGN);
}

pthread_mutex_t server_state_mutex;
char* server_state = "init";

void* irc_server(void*unused) {
	(void) unused;
	int err;
	struct addrinfo *res;
	struct addrinfo hint = {
		.ai_flags = AI_PASSIVE,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = 0,

		.ai_addrlen = 0,
		.ai_addr = 0,
		.ai_canonname = 0,
		.ai_next = 0
	};

	err = getaddrinfo("127.0.0.1", "6667", &hint, &res);
	if (err) {
		fatal("getaddrinfo(): %s", gai_strerror(err));
	}

	mylog(LOG_DEBUG, "socket");
	int listener_fd;
	if ((listener_fd = socket(res->ai_family, res->ai_socktype,
					res->ai_protocol)) < 0) {
		fatal("socket(): %s", gai_strerror(err));
	}

	mylog(LOG_DEBUG, "bind");
	if (bind(listener_fd, res->ai_addr, res->ai_addrlen) < 0) {
		fatal("bind(): %s", strerror(errno));
	}

	mylog(LOG_DEBUG, "listen");
	err = listen(listener_fd, 256);
	if (err == -1) {
		fatal("listen(): %s", strerror(errno));
	}

	pthread_mutex_lock(&server_state_mutex);
	server_state = "accepting";
	pthread_mutex_unlock(&server_state_mutex);

	struct sockaddr addr;
	socklen_t addrlen;
	mylog(LOG_DEBUG, "accept");
	int fd = accept(listener_fd, &addr, &addrlen);
	if (err == -1) {
		fatal("accept(): %s", strerror(errno));
	}
	mylog(LOG_DEBUG, "Accepted!");
	close(fd);
	close(listener_fd);

	// Make the tests thread quit irc_main.
	sighup = 1;
	return NULL;
}

START_TEST(test_irc_basic)
{
	pthread_mutex_init(&server_state_mutex, NULL);
	pthread_t thread;
	pthread_attr_t pthread_attr;
    assert(pthread_create(&thread, &pthread_attr, &irc_server, NULL) == 0);

	for (;;) {
		pthread_mutex_lock(&server_state_mutex);
		if (strcmp(server_state, "accepting") == 0) {
			break;
		}
		pthread_mutex_unlock(&server_state_mutex);
	}
	bip_t bip;
	bip_init(&bip);
	bip.listener = listener_new("127.0.0.1", 7777, NULL);
	assert(bip.listener);

	struct network* n;
	n = bip_calloc(sizeof(struct network), 1);
	hash_insert(&bip.networks, "localnetwork", n);
	n->serverv = bip_realloc(n->serverv, sizeof(struct server));
	n->serverc = 1;
	memset(&n->serverv[0], 0, sizeof(struct server));
	n->serverv[0].host = "127.0.0.1";
	n->serverv[0].port = 6667;

	struct bipuser*u;
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

	void* retval;
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
