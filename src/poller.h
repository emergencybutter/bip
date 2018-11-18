#ifndef POLLER_H_
#define POLLER_H_

#include "util.h"
#include <poll.h>

typedef enum {
	POLLER_NONE = 0,
	POLLER_IN = POLLIN,
	POLLER_OUT = POLLOUT,
	POLLER_HUP = POLLHUP
} poller_event_t;

typedef struct {
	int fd;
	int events;
	void (*on_in)(void *data);
	void (*on_out)(void *data);
	void (*on_hup)(void *data);
	void *data;
} descriptor_t;

typedef struct {
	hash_t fds;
	int timeout;
	void (*timed_out)(void *data);
	void *data;
	int want_exit;
	struct timespec last_timeout;
} poller_t;

#define INT_KEY(name, key)                                                     \
	char name[17];                                                         \
	sprintf(name, "%x", key);

poller_t *poller_create();
descriptor_t *poller_register(poller_t *p, int fd);
void poller_unregister(poller_t *p, int fd);
descriptor_t *poller_get_descriptor(poller_t *p, int fd);
void descriptor_set_events(descriptor_t *descriptor, poller_event_t events);
void descriptor_unset_events(descriptor_t *descriptor, poller_event_t events);
void poller_wait(poller_t *p, int timeout);
void poller_gettime(struct timespec *time);
void poller_loop(poller_t *poller);

#endif // POLLER_H_