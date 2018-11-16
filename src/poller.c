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
	return p;
}

descriptor_t *poller_new_descriptor(poller_t *p, int fd)
{
	INT_KEY(str, fd);
	descriptor_t *descriptor = bip_malloc(sizeof(descriptor_t));
	descriptor->fd = fd;
	int error = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (error < 0) {
		fatal("fcntl: %s", strerror(error));
	}
	descriptor->events = 0;
	descriptor->on_in = descriptor->on_out = descriptor->on_hup = NULL;
	descriptor->data = NULL;
	hash_insert(&p->fds, str, descriptor);
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

void poller_remove(poller_t *p, int fd)
{
	INT_KEY(str, fd);
	free(hash_get(&p->fds, str));
	hash_remove(&p->fds, str);
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
	for (int i = 0; i < num_fds; i++) {
		INT_KEY(str, fds[i].fd);
		descriptor_t *descriptor = hash_get(&p->fds, str);
		if (fds[i].revents & POLLIN)
			descriptor->on_in(descriptor->data);
		if (fds[i].revents & POLLOUT)
			descriptor->on_out(descriptor->data);
		if (fds[i].revents & POLLHUP)
			descriptor->on_hup(descriptor->data);
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

void poller_loop(poller_t *poller)
{
	poller_gettime(&poller->last_timeout);
	int timeout_ms = poller->timeout;
	while (!poller->want_exit) {
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
}