#include "poller.h"

#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/errno.h>
#include <fcntl.h>

poller_t *poller_create()
{
	poller_t *p = bip_malloc(sizeof(poller_t));
	hash_init(&p->fds, HASH_DEFAULT);
	p->timeout = -1;
	p->timed_out = NULL;
	p->want_exit = 0;
	poller_gettime(&p->last_timeout);
	return p;
}

static int socket_set_nonblock(int s)
{
	int flags;

	if ((flags = fcntl(s, F_GETFL, 0)) < 0) {
		mylog(LOG_ERROR, "Cannot set socket %d to non blocking : %s",
				s, strerror(errno));
		return 0;
	}

	if (fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0) {
		mylog(LOG_ERROR, "Cannot set socket %d to non blocking : %s",
				s, strerror(errno));
		return 0;
	}
	return 1;
}

descriptor_t *poller_register(poller_t *p, int fd)
{
	INT_KEY(str, fd);
	assert(hash_get(&p->fds, str) == NULL);
	descriptor_t *descriptor = bip_malloc(sizeof(descriptor_t));
	descriptor->fd = fd;
	socket_set_nonblock(fd);
	descriptor->events = 0;
	descriptor->on_in = descriptor->on_out = descriptor->on_hup = NULL;
	descriptor->data = NULL;
	descriptor->removed = 0;
	hash_insert(&p->fds, str, descriptor);
	return descriptor;
}

void poller_unregister(poller_t *p, int fd)
{
	INT_KEY(str, fd);
	descriptor_t* descriptor = hash_get(&p->fds, str);
	descriptor->removed = 1;
}

descriptor_t *poller_get_descriptor(poller_t *p, int fd)
{
	INT_KEY(str, fd);
	descriptor_t *descriptor = hash_get(&p->fds, str);
	assert(descriptor != NULL);
	return descriptor;
}

void descriptor_set_events(descriptor_t *descriptor, poller_event_t events)
{
	descriptor->events |= events;
}

void descriptor_unset_events(descriptor_t *descriptor, poller_event_t events)
{
	descriptor->events &= ~events;
}

void poller_wait(poller_t *p, int timeout)
{
	int tentative_num_fds = 16;
	struct pollfd *fds =
		bip_malloc(sizeof(struct pollfd) * tentative_num_fds);
	hash_iterator_t hi;
	int num_fds = 0;
	for (hash_it_init(&p->fds, &hi); hash_it_item(&hi); hash_it_next(&hi)) {
		descriptor_t *descriptor = hash_it_item(&hi);
		if (descriptor->removed) {
			hash_it_remove(&hi);
		}
		if (descriptor->events != 0) {
			num_fds++;
			if (num_fds > tentative_num_fds) {
				tentative_num_fds *= 2;
				struct pollfd *fds = bip_realloc(
					fds, sizeof(struct pollfd)
						     * tentative_num_fds);
			}
			fds[num_fds - 1].fd = descriptor->fd;
			fds[num_fds - 1].events = descriptor->events;
		}
	}
	int poll_ret = poll(fds, num_fds, timeout);
	if (poll_ret < 0) {
		fatal("poll: %s", strerror(errno));
	}
	int *removed_fds = bip_malloc(sizeof(int) * num_fds);
	int num_removed_fds = 0;
	for (int i = 0; i < num_fds; i++) {
		INT_KEY(str, fds[i].fd);
		descriptor_t *descriptor = hash_get(&p->fds, str);
		if (fds[i].revents & POLLIN)
			descriptor->on_in(descriptor->data);
		if (!descriptor->removed && fds[i].revents & POLLOUT)
			descriptor->on_out(descriptor->data);
		if (!descriptor->removed && fds[i].revents & POLLHUP)
			descriptor->on_hup(descriptor->data);
		if (descriptor->removed) {
			hash_remove(&p->fds, descriptor->fd);
			free(descriptor);
		}
	}
	free(fds);
}

void poller_gettime(struct timespec *time)
{
	int errtime = clock_gettime(CLOCK_MONOTONIC, time);
	if (errtime != 0) {
		fatal("clock_gettime: %s", strerror(errno));
	}
}

void poller_one_shot(poller_t* poller) {
	int timeout_ms = poller->timeout;

		poller_wait(poller, timeout_ms);
		struct timespec now;
		poller_gettime(&now);
		if (poller->timeout >= 0) {
			timeout_ms -=
				(now.tv_sec - poller->last_timeout.tv_sec)
					* 1000
				+ (now.tv_nsec - poller->last_timeout.tv_nsec)
					  / 1000;
			if (timeout_ms <= 0) {
				poller->timed_out(poller->data);
				timeout_ms = poller->timeout;
			}
		}
}

void poller_loop(poller_t *poller)
{
	poller_gettime(&poller->last_timeout);
	while (!poller->want_exit) {
		poller_one_shot(poller);
	}
}