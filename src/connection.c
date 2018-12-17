/*
 * $Id: connection.c,v 1.98 2005/04/12 19:34:35 nohar Exp $
 *
 * This file is part of the bip project
 * Copyright (C) 2004 2005 Arnaud Cornet and Loïc Gomez
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * See the file "COPYING" for the exact licensing terms.
 */

#include "config.h"
#include <sys/time.h>
#include <sys/errno.h>
#include <time.h>
#include "connection.h"
#include "path_util.h"
#include "poller.h"

#ifdef HAVE_LIBSSL
static int ssl_initialized = 0;
static int ssl_cx_idx;
extern FILE *conf_global_log_file;
static BIO *errbio = NULL;
extern char *conf_ssl_certfile;
extern char *conf_biphome;
extern char *conf_client_ciphers;
extern char *conf_client_dh_file;
static SSL_CTX *SSL_init_context(char *ciphers);
/* SSH like trust management */
int link_add_untrusted(void *ls, X509 *cert);
#endif

static int cn_want_write(connection_t *cn);
static int connection_timedout(connection_t *cn);
static int socket_set_nonblock(int s);
static void connection_connected(connection_t *c);
static void real_write_all(connection_t *cn);
static void real_read_all(connection_t *cn);
static int read_socket_SSL(connection_t *cn);
static int read_socket(connection_t *cn);
static void data_find_lines(connection_t *cn);
static int cn_is_in_error(connection_t *cn);
static void connection_save_endpoints(connection_t *c);
static int connection_want_write(connection_t *cn);
#ifdef HAVE_LIBSSL
static SSL_CTX *listener_ssl_context(listener_ssl_options_t *options);
#endif
static void reset_trigger(connection_t *cn);
static void connect_trynext(connection_t *cn);

void listener_ssl_options_init(listener_ssl_options_t *options)
{
	memset(options, 0, sizeof(listener_ssl_options_t));
}

void connection_ssl_options_init(connection_ssl_options_t *options)
{
	memset(options, 0, sizeof(connection_ssl_options_t));
	options->ssl_check_mode = SSL_CHECK_CA;
}

poller_t *global_poller()
{
	static poller_t *poller = NULL;
	if (poller == NULL) {
		poller = poller_create();
	}
	return poller;
}

struct connecting_data {
	struct addrinfo *dst;
	struct addrinfo *src;
	struct addrinfo *cur;
};

static void connecting_data_free(struct connecting_data *t)
{
	if (t->dst)
		freeaddrinfo(t->dst);
	if (t->src)
		freeaddrinfo(t->src);
	free(t);
}

void connection_close(connection_t *cn)
{
	mylog(LOG_DEBUG, "Connection close asked. FD:%d (status: %d)",
			(long)cn->handle, cn->connected);
	if (cn->connected != CONN_DISCONN && cn->connected != CONN_ERROR) {
		cn->connected = CONN_DISCONN;
		poller_unregister(global_poller(), cn->handle);
		if (close(cn->handle) == -1)
			mylog(LOG_WARN, "Error on socket close: %s",
			      strerror(errno));
		cn->handle = -1;
	}
}

void connection_free(connection_t *cn)
{
	connection_close(cn);

	if (cn->outgoing) {
		char *l;
		while ((l = list_remove_first(cn->outgoing)))
			free(l);
		list_free(cn->outgoing);
	}
	if (cn->incoming_lines) {
		char *l;
		while ((l = list_remove_first(cn->incoming_lines))) {
			log(LOG_WARN, "Closing connection with buffer: %s", l);
			free(l);
		}
		list_free(cn->incoming_lines);
	}
	if (cn->incoming)
		free(cn->incoming);
	if (cn->connecting_data)
		connecting_data_free(cn->connecting_data);
		/* conn->user_data */
#ifdef HAVE_LIBSSL
	if (cn->cert) {
		X509_free(cn->cert);
		cn->cert = NULL;
	}
	if (cn->ssl_h) {
		SSL_shutdown(cn->ssl_h);
		SSL_free(cn->ssl_h);
		cn->ssl_h = NULL;
	}
	if (cn->ssl_ctx_h) {
		SSL_CTX_free(cn->ssl_ctx_h);
		cn->ssl_ctx_h = NULL;
	}
#endif
	if (cn->localip) {
		free(cn->localip);
		cn->localip = NULL;
	}
	if (cn->remoteip) {
		free(cn->remoteip);
		cn->remoteip = NULL;
	}
	free(cn);
}

#ifdef HAVE_LIBSSL
// Turns either a new client or a newly accepted socket to an SSL socket.
static void connection_sslize(connection_t *cn)
{
	log(LOG_DEBUG, "fd: %d, connection_sslize %d", cn->handle,
	    cn->ssl_client);

	descriptor_t *descriptor =
		poller_get_descriptor(global_poller(), cn->handle);
	int err;
	if (cn->ssl_client) {
		err = SSL_connect(cn->ssl_h);
	} else {
		err = SSL_accept(cn->ssl_h);
	}
	int ssl_err = 0;
	ssl_err = SSL_get_error(cn->ssl_h, err);
	switch (ssl_err) {
	case SSL_ERROR_WANT_READ:
		break;
	case SSL_ERROR_WANT_WRITE:
		cn->need_write = 1;
		break;
	case SSL_ERROR_ZERO_RETURN:
		mylog(LOG_ERROR, "SSL_ERROR_ZERO_RETURN during handshake");
		connection_close(cn);
		cn->connected = CONN_ERROR;
		break;
	case SSL_ERROR_SSL:
		mylog(LOG_ERROR, "SSL_ERROR_SSL during handshake");
		connection_close(cn);
		cn->connected = CONN_ERROR;
		break;
	case SSL_ERROR_SYSCALL:
		mylog(LOG_ERROR, "SSL_ERROR_SYSCALL during handshake");
		connection_close(cn);
		break;
	case SSL_ERROR_NONE: {
		log(LOG_DEBUG, "none");
		const SSL_CIPHER *cipher;
		char buf[128];
		int len;

		cipher = SSL_get_current_cipher(cn->ssl_h);
		SSL_CIPHER_description(cipher, buf, 128);
		len = strlen(buf);
		if (len > 0)
			buf[len - 1] = '\0';
		log(LOG_DEBUG, "fd: %d, Negociated ciphers: %s", cn->handle,
		    buf);
		log(LOG_DEBUG, "fd: %d, ssl_check_mode: %d", cn->handle,
		    cn->ssl_check_mode);

		switch (cn->ssl_check_mode) {
		case SSL_CHECK_NONE:
			log(LOG_DEBUG, "fd: %d, connected (SSL)", cn->handle);
			cn->connected = CONN_OK;
			break;
		case SSL_CHECK_BASIC:
			if ((err = SSL_get_verify_result(cn->ssl_h))
			    != X509_V_OK) {
				mylog(LOG_ERROR,
				      "Certificate check failed: %s (%d)!",
				      X509_verify_cert_error_string(err), err);
				cn->connected = CONN_UNTRUSTED;
				break;
			}
			cn->connected = CONN_OK;
			break;
		case SSL_CHECK_CA:
			if ((err = SSL_get_verify_result(cn->ssl_h))
			    != X509_V_OK) {
				mylog(LOG_ERROR,
				      "Certificate check failed: %s (%d)!",
				      X509_verify_cert_error_string(err), err);
				cn->connected = CONN_UNTRUSTED;
				break;
			}
			cn->connected = CONN_OK;
			break;
		default:
			fatal("Unknown ssl_check_mode");
		}
		break;
	}
	default: {
		fatal("Unknown SSL Error: %d, %d.", err, ssl_err);
		break;
	}
	} // switch
	reset_trigger(cn);
}
#endif

static void listener_on_in(void *data)
{
	listener_t *listener = data;
	log(LOG_DEBUG, "fd: %d, listener_on_in", listener->handle);
	connection_t *connection = accept_new(listener);
	assert(connection != NULL);
	list_add_last(&listener->accepted_connections, connection);
	connection->user_data = listener->user_data;
}

static void listener_on_out(void *data)
{
	listener_t *listener = data;
	log(LOG_DEBUG, "fd: %d, listener_on_out", listener->handle);
}

static void listener_on_hup(void *data)
{
	listener_t *listener = data;
	log(LOG_DEBUG, "fd: %d, on_hup", listener->handle);
}

static void connection_client_on_in(void *data)
{
	connection_t *cn = data;
	log(LOG_DEBUG, "fd: %d, connection_client_on_in connected: %d",
	    cn->handle, cn->connected);
	switch (cn->connected) {
#ifdef HAVE_LIBSSL
	case CONN_SSL_CONNECT:
		connection_sslize(cn);
		break;
#endif
	case CONN_OK:
		real_write_all(cn);
		real_read_all(cn);
		log(LOG_DEBUG, "fd: %d, num lines after read: %d", cn->handle,
		    list_count(cn->incoming_lines));
		break;
	default:
		fatal("Unknown connect state: %d", cn->connected);
	}
}

void real_read_all(connection_t *cn)
{
	int ret;
#ifdef HAVE_LIBSSL
	if (cn->ssl_ctx_h)
		ret = read_socket_SSL(cn);
	else
#endif
		ret = read_socket(cn);
	if (!cn_is_connected(cn)) {
		return;
	}

	if (cn->incoming_lines == NULL)
		cn->incoming_lines = list_new(list_ptr_cmp);
	data_find_lines(cn);
	reset_trigger(cn);
}

static void connection_client_on_out(void *data)
{
	connection_t *cn = data;
	cn->need_write = 0;
	if (cn_is_in_error(cn)) {
		mylog(LOG_ERROR, "Error on fd %d (state %d)", cn->handle,
		      cn->connected);
		connection_close(cn);
		return;
	}
	switch (cn->connected) {
	case CONN_INPROGRESS: {
		int optval = -1;
		socklen_t optlen = sizeof(optval);
		int err = getsockopt(cn->handle, SOL_SOCKET, SO_ERROR, &optval,
				     &optlen);
		if (optval != 0) {
			connection_close(cn);
			return;
		}
		if (cn->connecting_data) {
			connecting_data_free(cn->connecting_data);
			cn->connecting_data = NULL;
		}
		log(LOG_DEBUG, "fd: %d, Socket connected (TCP)", cn->handle);
		connection_save_endpoints(cn);
#ifdef HAVE_LIBSSL
		if (cn->ssl_ctx_h) {
			cn->connected = CONN_SSL_CONNECT;
			cn->need_write = 1;
			if (!SSL_set_fd(cn->ssl_h, cn->handle)) {
				mylog(LOG_ERROR,
				      "unable to associate FD to SSL "
				      "structure");
				connection_close(cn);
				cn->connected = CONN_ERROR;
				return;
			}
			break;
		}
#endif
		cn->connected = CONN_OK;
		break;
	}
	case CONN_OK:
		real_write_all(cn);
		real_read_all(cn);
		break;
#ifdef HAVE_LIBSSL
	case CONN_SSL_CONNECT:
		connection_sslize(cn);
		break;
#endif
	default:
		fatal("Unknown client connect state: %d", cn->connected);
	}
	reset_trigger(cn);
}

static void connection_client_on_hup(void *data)
{
	connection_t *cn = data;
	mylog(LOG_ERROR, "fd: %d, Disconnection.", cn->handle);
	connection_close(data);
}

static char *bip_ntop(struct sockaddr *addr, int *port)
{
	char *ip = bip_malloc(128);
	ip[127] = 0;
	switch (addr->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr, ip,
			  127);
		*port = ntohs(((struct sockaddr_in *)addr)->sin_port);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr,
			  ip, 127);
		*port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
		break;
	default:
		strcpy(ip, "unknown family");
		*port = 0;
		break;
	}
	return ip;
}

static void connect_trynext(connection_t *cn)
{
	struct addrinfo *cur;
	int err;

	if (!cn->connecting_data)
		fatal("called connect_trynext with a connection not "
		      "connecting\n");

	cur = cn->connecting_data->cur;

	for (cur = cn->connecting_data->cur; cur; cur = cur->ai_next) {
		if ((cn->handle = socket(cur->ai_family, cur->ai_socktype,
					 cur->ai_protocol))
		    < 0) {
			mylog(LOG_WARN, "socket() : %s", strerror(errno));
			continue;
		}

		descriptor_t *descriptor =
			poller_register(global_poller(), cn->handle);
		descriptor->on_in = connection_client_on_in;
		descriptor->on_out = connection_client_on_out;
		descriptor->on_hup = connection_client_on_hup;
		descriptor->data = cn;

		if (cn->connecting_data->src) {
			/* local bind */
			err = bind(cn->handle,
				   cn->connecting_data->src->ai_addr,
				   cn->connecting_data->src->ai_addrlen);
			if (err == -1)
				mylog(LOG_WARN, "bind() before connect: %s",
				      strerror(errno));
			connection_close(cn);
		}

		err = connect(cn->handle, cur->ai_addr, cur->ai_addrlen);
		if (err == -1 && errno != EINPROGRESS) {
			/* connect() failed */
			int port = 0;
			char *ip = bip_ntop(cur->ai_addr, &port);
			mylog(LOG_WARN, "connect(%s:%d): %d", ip, port,
			      strerror(errno));
			free(ip);
			connection_close(cn);
		} else {
			int port = 0;
			char *ip = bip_ntop(cur->ai_addr, &port);
			log(LOG_DEBUG, "fd: %d, connect(%s:%d)", cn->handle, ip,
			    port);
			free(ip);
		}

		// Regardless of if we got EINPROGRESS or SUCCESS, we simply
		// wait for 'POLLER_OUT' to move the state machine.
		/* next time try the next in the list */
		cn->connecting_data->cur = cur->ai_next;
		cn->connect_time = time(NULL);
		cn->connected = CONN_INPROGRESS;
		cn->need_write = 1;
		reset_trigger(cn);
		return;
	}

	cn->connected = CONN_ERROR;
	connecting_data_free(cn->connecting_data);
	cn->connecting_data = NULL;
	mylog(LOG_ERROR, "connect() failed.");
}

#ifdef HAVE_LIBSSL
static X509 *mySSL_get_cert(SSL *ssl)
{
	X509 *cert;

	if (!ssl) {
		mylog(LOG_ERROR, "mySSL_get_cert() No SSL context");
		return NULL;
	}
	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL)
		mylog(LOG_WARN,
		      "mySSL_get_cert() SSL server supplied no "
		      "certificate !");
	return cert;
}

static int _write_socket_SSL(connection_t *cn, char *message)
{
	int count, size;

	size = strlen(message);

	if (cn->ssl_client == 1 && cn->cert == NULL) {
		cn->cert = mySSL_get_cert(cn->ssl_h);
		if (cn->cert == NULL) {
			mylog(LOG_ERROR, "No certificate in SSL write_socket");
			return WRITE_ERROR;
		}
	}
	if (!bucket_try_remove(&cn->bucket, size)) {
		return WRITE_KEEP;
	}
	count = SSL_write(cn->ssl_h, (const void *)message, size);
	ERR_print_errors(errbio);
	if (count <= 0) {
		int err = SSL_get_error(cn->ssl_h, count);
		switch (err) {
		case SSL_ERROR_WANT_READ:
			return WRITE_KEEP;
		case SSL_ERROR_WANT_WRITE:
			cn->need_write = 1;
			return WRITE_KEEP;
		default:
			connection_close(cn);
			return WRITE_ERROR;
		}
		return WRITE_KEEP;
	}
	if (count != size) {
		/* abnormal : openssl keeps writing until message is not fully
		 * sent */
		log(LOG_DEBUG, "only %d written while message length is %d",
		    count, size);
	}
	return WRITE_OK;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_OBJECT_get0_X509(o) ((o)->data.x509)
#define X509_STORE_CTX_get_by_subject(vs, type, name, ret)                     \
	X509_STORE_get_by_subject(vs, type, name, ret)

X509_OBJECT *X509_OBJECT_new()
{
	X509_OBJECT *ret = OPENSSL_malloc(sizeof(*ret));

	if (ret != NULL) {
		memset(ret, 0, sizeof(*ret));
		ret->type = X509_LU_FAIL;
	} else {
		X509err(X509_F_X509_VERIFY_CERT, ERR_R_MALLOC_FAILURE);
	}
	return ret;
}

void X509_OBJECT_free(X509_OBJECT *a)
{
	if (a == NULL)
		return;
	switch (a->type) {
	default:
		break;
	case X509_LU_X509:
		X509_free(a->data.x509);
		break;
	case X509_LU_CRL:
		X509_CRL_free(a->data.crl);
		break;
	}
	OPENSSL_free(a);
}
#endif
#endif

static int _write_socket(connection_t *cn, char *message)
{
	size_t size;
	size_t tcount = 0;
	ssize_t count;

	size = strlen(message);
	if (size == 0) {
		return WRITE_OK;
	}
	if (!bucket_try_remove(&cn->bucket, size)) {
		return WRITE_KEEP;
	}

	/* loop if we wrote some data but not everything, or if error is
	 * EINTR */
	do {
		count = write(cn->handle, ((const char *)message) + tcount,
			      size - tcount);
		if (count > 0) {
			tcount += count;
			if (tcount == size) {
				log(LOG_DEBUG, "fd: %d, WRITTEN: %s",
				    cn->handle, message);
				return WRITE_OK;
			}
		}
	} while (count > 0 || (count < 0 && errno == EINTR));

	/* If we reach this point, we have a partial write */
	assert(count != 0);

	/* if no fatal error, return WRITE_KEEP, which makes caller keep line
	 * in its FIFO
	 *
	 * Shitty: we might have written a partial line, so we hack the line...
	 * Callers of _write_socket muse provide a writable message
	 */
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
		memmove(message, message + tcount, size - tcount + 1);
		bucket_add(&cn->bucket, size - tcount);
		return WRITE_KEEP;
	}
	/* other errors, EPIPE or worse, close the connection, repport error */
	if (cn_is_connected(cn)) {
		if (errno != EPIPE)
			mylog(LOG_INFO, "Broken socket: %s.", strerror(errno));
		connection_close(cn);
	}
	return WRITE_ERROR;
}

static int write_socket(connection_t *cn, char *line)
{
#ifdef HAVE_LIBSSL
	if (cn->ssl_ctx_h)
		return _write_socket_SSL(cn, line);
	else
#endif
		return _write_socket(cn, line);
}

static void real_write_all(connection_t *cn)
{
	int ret;
	char *line;

	if (cn == NULL)
		fatal("real_write_all: wrong arguments");

	if (cn->partial == NULL && list_is_empty(cn->outgoing)) {
		reset_trigger(cn);
		return;
	}

	if (cn->partial) {
		line = cn->partial;
		cn->partial = NULL;
	} else {
		line = list_remove_first(cn->outgoing);
	}

	do {
		ret = write_socket(cn, line);
		switch (ret) {
		case WRITE_ERROR:
			/* we might as well free(line) here */
			list_add_first(cn->outgoing, line);
			connection_close(cn);
			return;
		case WRITE_KEEP:
			/* interrupted or not ready */
			assert(cn->partial == NULL);
			cn->partial = line;
			break;
		case WRITE_OK:
			free(line);
			break;
		default:
			fatal("internal error 6");
			break;
		}
	} while ((line = list_remove_first(cn->outgoing)));
	reset_trigger(cn);
}

static void reset_trigger(connection_t *cn)
{
	if (cn->handle == -1) {
		return;
	}
	descriptor_t *descriptor =
		poller_get_descriptor(global_poller(), cn->handle);
	if (connection_want_write(cn) || cn->need_write) {
		descriptor_set_events(descriptor, POLLER_OUT);
	} else {
		descriptor_unset_events(descriptor, POLLER_OUT);
	}
	descriptor_set_events(descriptor, POLLER_IN);
}

/*
 * skips to the head of the queue.
 */
void write_line_fast(connection_t *cn, char *line)
{
	int r;
	char *nline = bip_strdup(line);
	list_add_first(cn->outgoing, nline);
	reset_trigger(cn);
}

void write_lines(connection_t *cn, list_t *lines)
{
	list_append(cn->outgoing, lines);
	reset_trigger(cn);
}

void write_line(connection_t *cn, char *line)
{
	list_add_last(cn->outgoing, bip_strdup(line));
	reset_trigger(cn);
}

list_t *read_lines(connection_t *cn, int *error)
{
	list_t *ret = NULL;

	switch (cn->connected) {
	case CONN_TIMEOUT:
	case CONN_ERROR:
	case CONN_DISCONN:
	case CONN_EXCEPT:
	case CONN_UNTRUSTED:
		*error = 1;
		ret = NULL;
		break;
	case CONN_NEW:
	case CONN_INPROGRESS:
		*error = 0;
		ret = NULL;
		break;
	case CONN_OK:
		*error = 0;
		ret = cn->incoming_lines;
		cn->incoming_lines = list_new(list_ptr_cmp);
		break;
	default:
		fatal("fd: %d: bad state: %d", cn->handle, cn->connected);
		break;
	}
	return ret;
}

#ifdef HAVE_LIBSSL

static int read_socket_SSL(connection_t *cn)
{
	int max, count;
	log(LOG_DEBUG, "fd: %d, read_socket_SSL %d, %d", cn->handle,
	    cn->incoming_end, cn->connected);
	max = CONN_BUFFER_SIZE - cn->incoming_end;
	if (cn->ssl_client && cn->cert == NULL) {
		cn->cert = mySSL_get_cert(cn->ssl_h);
		if (cn->cert == NULL) {
			mylog(LOG_ERROR, "No certificate in SSL read_socket");
			return READ_ERROR;
		}
	}
	count = SSL_read(cn->ssl_h, (void *)cn->incoming + cn->incoming_end,
			 max);
	ERR_print_errors(errbio);
	if (count < 0) {
		int err = SSL_get_error(cn->ssl_h, count);
		if (err == SSL_ERROR_WANT_READ) {
			log(LOG_DEBUG, "fd: %d, read want read", cn->handle);
			reset_trigger(cn);
			return READ_OK;
		}
		if (err == SSL_ERROR_WANT_WRITE) {
			log(LOG_DEBUG, "fd: %d, read want write", cn->handle);
			cn->need_write = 1;
			reset_trigger(cn);
			return READ_OK;
		}
		mylog(LOG_ERROR, "fd %d: Connection error", cn->handle);
		connection_close(cn);
		return READ_ERROR;
	} else if (count == 0) {
		mylog(LOG_ERROR, "fd %d: Connection lost", cn->handle);
		connection_close(cn);
		return READ_ERROR;
	}

	cn->incoming_end += count;
	return READ_OK;
}
#endif

/* returns 1 if connection must be notified */
static int read_socket(connection_t *cn)
{
	int max, count;
	assert(cn != NULL);
	max = CONN_BUFFER_SIZE - cn->incoming_end;
	count = read(cn->handle, cn->incoming + cn->incoming_end, max);
	if (count < 0) {
		if (errno == EAGAIN || errno == EINTR || errno == EINPROGRESS) {
			reset_trigger(cn);
			return READ_OK;
		}
		mylog(LOG_ERROR, "read(fd=%d): Connection error: %s",
		      cn->handle, strerror(errno));
		connection_close(cn);
		return READ_ERROR;
	} else if (count == 0) {
		mylog(LOG_ERROR, "read(fd=%d): Connection lost: %s", cn->handle,
		      strerror(errno));
		connection_close(cn);
		return READ_ERROR;
	}
	cn->incoming[cn->incoming_end + count] = 0;
	log(LOG_DEBUG, "fd: %d, READ: %s", cn->handle,
	    cn->incoming + cn->incoming_end);

	cn->incoming_end += count;
	return READ_OK;
}

static void data_find_lines(connection_t *cn)
{
	size_t len = 0, lastlen = 0, ssz;
	char *p = cn->incoming;
	char *buf;

	for (;;) {
		while (len < cn->incoming_end && p[len] != '\n')
			len++;
		if (len >= cn->incoming_end || p[len] != '\n')
			break;

		ssz = len - lastlen;
		if (ssz >= 1) {
			if (p[len - 1] == '\r')
				ssz--;
			buf = bip_malloc(ssz + 1);
			memcpy(buf, p + lastlen, ssz);
			buf[ssz] = 0;

			list_add_last(cn->incoming_lines, buf);
		}

		len++;
		lastlen = len;
	}
	if (lastlen) {
		unsigned i;
		for (i = 0; i < cn->incoming_end - lastlen; i++)
			p[i] = p[i + lastlen];
		cn->incoming_end -= lastlen;
	}
}

int cn_is_new(connection_t *cn)
{
	switch (cn->connected) {
	case CONN_TIMEOUT:
	case CONN_ERROR:
	case CONN_DISCONN:
	case CONN_EXCEPT:
	case CONN_OK:
	case CONN_UNTRUSTED:
		return 0;
	case CONN_NEW:
	case CONN_INPROGRESS:
		return 1;
	default:
		fatal("internal error 9");
		return 0;
	}
}

static int cn_is_in_error(connection_t *cn)
{
	switch (cn->connected) {
	case CONN_TIMEOUT:
	case CONN_ERROR:
	case CONN_DISCONN:
	case CONN_EXCEPT:
	case CONN_UNTRUSTED:
		return 1;
	case CONN_NEW:
	case CONN_INPROGRESS:
	case CONN_OK:
	case CONN_SSL_CONNECT:
		return 0;
	default:
		fatal("internal error 10");
		return 1;
	}
}

int cn_is_connected(connection_t *cn)
{
	if (cn == NULL)
		fatal("cn_is_connected, wrong argument");
	return (cn->connected == CONN_OK);
}

static void connection_save_endpoints(connection_t *c)
{
	if (c->localip)
		free(c->localip);
	c->localip = connection_localip(c);
	c->localport = connection_localport(c);
	if (c->remoteip)
		free(c->remoteip);
	c->remoteip = connection_remoteip(c);
	c->remoteport = connection_remoteport(c);
	log(LOG_DEBUG, "fd:%d endpoints local: %s:%d remote:%s:%d", c->handle,
	    c->localip, c->localport, c->remoteip, c->remoteport);
}

static int connection_want_write(connection_t *cn)
{
	if (list_is_empty(cn->outgoing)) {
		return 0;
	}
	if (cn->partial != NULL)
		return bucket_contains(&cn->bucket, strlen(cn->partial));
	if (!list_is_empty(cn->outgoing)) {
		return bucket_contains(&cn->bucket,
				       strlen(list_get_first(cn->outgoing)));
	}
	return 0;
}

void connection_tick(connection_t *connection) {
	bucket_refill(&connection->bucket);
}

void increment_pointee(void *data)
{
	int *p = data;
	(*p)++;
}

void wait_event(list_t *listeners_list, list_t *cn_list, int *msec)
{
	int timedout = 0;
	global_poller()->timeout = *msec;
	global_poller()->timed_out = &increment_pointee;
	global_poller()->data = &timedout;

	struct timespec before;
	bip_gettime(&before);
	poller_wait(global_poller(), *msec);
	struct timespec after;
	bip_gettime(&after);
	if (timedout) {
		*msec = 0;
	} else {
		*msec -= (after.tv_sec - before.tv_sec) * 1000
			 + (after.tv_nsec - before.tv_nsec) / 1000000;
		if (*msec < 0)
			*msec = 0;
	}
}

static void create_socket(char *dsthostname, char *dstport, char *srchostname,
			  char *srcport, connection_t *cn)
{
	int err;
	struct connecting_data *cdata;
	struct addrinfo hint;

	log(LOG_DEBUG, "create_socket %s %s src: %s %s", dsthostname, dstport,
	    srchostname, srcport);

	memset(&hint, 0, sizeof(hint));
	hint.ai_flags = AI_PASSIVE;
	hint.ai_family = PF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = 0;

	cn->connected = CONN_ERROR;
	cdata = (struct connecting_data *)bip_malloc(
		sizeof(struct connecting_data));
	cdata->dst = cdata->src = cdata->cur = NULL;

	err = getaddrinfo(dsthostname, dstport, &hint, &cdata->dst);
	if (err) {
		mylog(LOG_ERROR, "getaddrinfo(%s): %s", dsthostname,
		      gai_strerror(err));
		connecting_data_free(cdata);
		cdata = NULL;
		return;
	}

	if (srchostname || srcport) {
		if ((err = getaddrinfo(srchostname, srcport, &hint,
				       &cdata->src))) {
			/* not fatal ? maybe a config option is needed */
			mylog(LOG_ERROR, "getaddrinfo(src): %s",
			      gai_strerror(err));
			cdata->src = NULL;
		}
	}

	cdata->cur = cdata->dst;
	cn->connecting_data = cdata;

	connect_trynext(cn);
}

static void create_listening_socket(char *hostname, char *port, listener_t *cn)
{
	cn->state = LISTEN_ERROR;
	int multi_client = 1;
	int err;
	struct addrinfo *res, *cur;
	struct addrinfo hint = {.ai_flags = AI_PASSIVE,
				.ai_family = AF_UNSPEC,
				.ai_socktype = SOCK_STREAM,
				.ai_protocol = 0,

				.ai_addrlen = 0,
				.ai_addr = 0,
				.ai_canonname = 0,
				.ai_next = 0};

	err = getaddrinfo(hostname, port, &hint, &res);
	if (err) {
		mylog(LOG_ERROR, "getaddrinfo(): %s", gai_strerror(err));
		return;
	}

	for (cur = res; cur; cur = cur->ai_next) {
		if ((cn->handle = socket(cur->ai_family, cur->ai_socktype,
					 cur->ai_protocol))
		    < 0) {
			mylog(LOG_WARN, "socket : %s", strerror(errno));
			continue;
		}

		if (setsockopt(cn->handle, SOL_SOCKET, SO_REUSEADDR,
			       (char *)&multi_client, sizeof(multi_client))
		    < 0) {
			mylog(LOG_WARN, "setsockopt() : %s", strerror(errno));
			close(cn->handle);
			cn->handle = -1;
			continue;
		}

		socket_set_nonblock(cn->handle);

		if (bind(cn->handle, cur->ai_addr, cur->ai_addrlen) < 0) {
			mylog(LOG_WARN, "bind() : %s", strerror(errno));
			close(cn->handle);
			cn->handle = -1;
			continue;
		}

		err = listen(cn->handle, 256);
		if (err == -1) {
			mylog(LOG_WARN, "listen() : %s", strerror(errno));
			close(cn->handle);
			cn->handle = -1;
			continue;
		}

		descriptor_t *descriptor =
			poller_register(global_poller(), cn->handle);
		descriptor->on_in = listener_on_in;
		descriptor->on_out = listener_on_out;
		descriptor->on_hup = listener_on_hup;
		descriptor->data = cn;
		descriptor_set_events(descriptor, POLLER_IN);

		freeaddrinfo(res);
		cn->state = LISTEN_OK;
		return;
	}
	freeaddrinfo(res);
	mylog(LOG_ERROR, "Unable to bind/listen");
}

int default_items_per_sec = 70;
int default_max_items = 70 * 3;

static connection_t *connection_init(int timeout, int listen)
{
	connection_t *conn;
	char *incoming;
	list_t *outgoing;

	conn = (connection_t *)bip_calloc(sizeof(connection_t), 1);
	incoming = (char *)bip_malloc(CONN_BUFFER_SIZE);
	outgoing = list_new(NULL);

	bucket_init(&conn->bucket, default_items_per_sec,
		    default_max_items);
	conn->timeout = (listen ? 0 : timeout);
	conn->connect_time = 0;
	conn->incoming = incoming;
	conn->incoming_end = 0;
	conn->outgoing = outgoing;
	conn->incoming_lines = list_new(list_ptr_cmp);
	conn->user_data = NULL;
	conn->listening = listen;
	conn->handle = -1;
	conn->ssl_client = 1;
	conn->connecting_data = NULL;
#ifdef HAVE_LIBSSL
	conn->ssl_ctx_h = NULL;
	conn->ssl_h = NULL;
	conn->cert = NULL;
	conn->ssl_check_mode = SSL_CHECK_NONE;
#endif
	conn->connected = CONN_NEW;
	return conn;
}

#ifdef HAVE_LIBSSL
static int connection_ssl_ctx_set_dh(SSL_CTX *ctx, const char *dh_file)
{
	/* Return ephemeral DH parameters. */
	DH *dh = NULL;
	FILE *f;
	int ret;

	if ((f = fopen(dh_file, "r")) == NULL) {
		mylog(LOG_ERROR, "Unable to open DH parameters (%s): %s",
		      dh_file, strerror(errno));
		return 0;
	}

	dh = PEM_read_DHparams(f, NULL, NULL, NULL);
	fclose(f);

	if (dh == NULL) {
		mylog(LOG_ERROR, "Could not parse DH parameters from: %s",
		      conf_client_dh_file);
		return 0;
	}

	ret = SSL_CTX_set_tmp_dh(ctx, dh);
	DH_free(dh);

	if (ret != 1) {
		mylog(LOG_ERROR, "Unable to set DH parameters: %s",
		      ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}

	return 1;
}
#endif

connection_t *accept_new(listener_t *listener)
{
	connection_t *conn;
	int handle;
	socklen_t sa_len = sizeof(struct sockaddr);
	struct sockaddr sa;

	handle = accept(listener->handle, &sa, &sa_len);
	log(LOG_DEBUG, "Accepted from %d, new fd: %d", listener->handle,
	    handle);
	if (handle < 0) {
		fatal("accept failed: %s", strerror(errno));
	}

	socket_set_nonblock(handle);

	conn = connection_init(listener->timeout, /*listen=*/1);
	conn->connect_time = time(NULL);
	conn->user_data = listener->user_data;
	conn->handle = handle;
	conn->ssl_client = 0;
	conn->connected = CONN_INPROGRESS;

	descriptor_t *descriptor =
		poller_register(global_poller(), conn->handle);
	descriptor->on_in = connection_client_on_in;
	descriptor->on_out = connection_client_on_out;
	descriptor->on_hup = connection_client_on_hup;
	descriptor->data = conn;

	descriptor_set_events(descriptor, POLLER_OUT);

#ifdef HAVE_LIBSSL
	if (listener->ssl_context) {
		conn->ssl_h = SSL_new(listener->ssl_context);
		if (!conn->ssl_h) {
			connection_free(conn);
			return NULL;
		}
		conn->ssl_ctx_h = listener->ssl_context;
		if (!SSL_set_fd(conn->ssl_h, conn->handle)) {
			mylog(LOG_ERROR,
			      "unable to associate FD to SSL "
			      "structure");
			conn->connected = CONN_ERROR;
			return conn;
		}
		SSL_set_accept_state(conn->ssl_h);
	}
#endif
	return conn;
}

listener_t *listener_new(char *hostname, int port,
			 listener_ssl_options_t *options)
{
	listener_t *listener = bip_malloc(sizeof(listener_t));
	listener_init(listener, hostname, port, options);
	return listener;
}

void listener_init(listener_t *listener, char *hostname, int port,
		   listener_ssl_options_t *options)
{
	list_init(&listener->accepted_connections, list_ptr_cmp);
	listener->localip = strdup(hostname);
	listener->localport = port;

	char portbuf[20];
	/* TODO: allow litteral service name in the function interface */
	if (snprintf(portbuf, 20, "%d", port) >= 20)
		portbuf[19] = '\0';

	create_listening_socket(hostname, portbuf, listener);
#ifdef HAVE_LIBSSL
	listener->ssl_context = NULL;
	if (options != NULL) {
		listener->ssl_context = listener_ssl_context(options);
		if (listener->ssl_context == NULL) {
			fatal("Could not initialize SSL subsystem.");
		}
	}
#else
	(void)options;
#endif
}

static connection_t *_connection_new(char *dsthostname, char *dstport,
				     char *srchostname, char *srcport,
				     int timeout)
{
	connection_t *conn;

	conn = connection_init(timeout, /*listen=*/0);
	create_socket(dsthostname, dstport, srchostname, srcport, conn);

	return conn;
}

#ifdef HAVE_LIBSSL

void connection_ssl_initialize()
{
	static int initialized = 0;
	if (initialized) {
		return;
	}
	initialized = 1;

	int ret, rng;

	SSL_library_init();
	SSL_load_error_strings();
	errbio = BIO_new_fp(conf_global_log_file, BIO_NOCLOSE);

	ssl_cx_idx =
		SSL_get_ex_new_index(0, "bip connection_t", NULL, NULL, NULL);

	int flags = O_RDONLY | O_NONBLOCK;
	int fd = open("/dev/random", flags);
	if (fd < 0) {
		mylog(LOG_WARN,
		      "SSL: /dev/random not ready, unable "
		      "to manually seed PRNG.");
		goto prng_end;
	}

	do {
		char buf[1025];
		int ret = read(fd, buf, 1024);
		if (ret <= 0) {
			mylog(LOG_ERROR, "/dev/random: %s", strerror(errno));
			goto prng_end;
		}
		log(LOG_DEBUG,
		    "PRNG seeded with %d /dev/random "
		    "bytes",
		    ret);
		RAND_seed(buf, ret);
	} while (!(rng = RAND_status()));

prng_end:
	do {
		ret = close(fd);
	} while (ret != 0 && errno == EINTR);
	if (RAND_status()) {
		log(LOG_DEBUG, "SSL: PRNG is seeded !");
	} else {
		mylog(LOG_WARN, "SSL: PRNG is not seeded enough");
		mylog(LOG_WARN,
		      "     OpenSSL will use /dev/urandom if "
		      "available.");
	}
}

static SSL_CTX *connection_create_ssl_context(char *ciphers)
{
	SSL_CTX *ctx;

	if (!(ctx = SSL_CTX_new(SSLv23_method()))) {
		ERR_print_errors(errbio);
		return NULL;
	}
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
	SSL_CTX_set_timeout(ctx, (long)60);
	SSL_CTX_set_options(ctx, SSL_OP_ALL);
	if (ciphers && !SSL_CTX_set_cipher_list(ctx, ciphers)) {
		SSL_CTX_free(ctx);
		return NULL;
	}

	return ctx;
}

static SSL_CTX *listener_ssl_context(listener_ssl_options_t *options)
{
	SSL_CTX *sslctx = NULL;
	if (!(sslctx = connection_create_ssl_context(options->ciphers))) {
		mylog(LOG_ERROR,
		      "SSL context initialization "
		      "failed");
		return NULL;
	}

	if (options->dh_file) {
		if (!connection_ssl_ctx_set_dh(sslctx, options->dh_file)) {
			mylog(LOG_ERROR, "SSL Unable to load DH parameters");
			return NULL;
		}
	}

	if (!SSL_CTX_use_certificate_chain_file(sslctx, options->cert_pem_file))
		mylog(LOG_WARN, "SSL: Unable to load certificate file");
	if (!SSL_CTX_use_PrivateKey_file(sslctx, options->cert_pem_file,
					 SSL_FILETYPE_PEM))
		mylog(LOG_WARN, "SSL: Unable to load key file");

	return sslctx;
}

static int bip_ssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	char subject[256];
	char issuer[256];
	X509 *err_cert;
	int err, depth;
	SSL *ssl;
	connection_t *c;
	X509_OBJECT *xobj;
	int result;

	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	/* Retrieve the SSL and connection_t objects from the store */
	ssl = X509_STORE_CTX_get_ex_data(ctx,
					 SSL_get_ex_data_X509_STORE_CTX_idx());
	c = SSL_get_ex_data(ssl, ssl_cx_idx);

	mylog(LOG_INFO, "SSL cert check: now at depth=%d", depth);
	X509_NAME_oneline(X509_get_subject_name(err_cert), subject, 256);
	X509_NAME_oneline(X509_get_issuer_name(err_cert), issuer, 256);
	mylog(LOG_INFO, "Subject: %s", subject);
	mylog(LOG_INFO, "Issuer: %s", issuer);

	result = preverify_ok;

	/* in basic mode (mode 1), accept a leaf certificate if we can find it
	 * in the store */
	if (c->ssl_check_mode == SSL_CHECK_BASIC && result == 0
	    && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
		|| err == X509_V_ERR_CERT_UNTRUSTED
		|| err == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
		|| err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
		|| err == X509_V_ERR_CERT_HAS_EXPIRED
		|| err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)) {

		if (!(xobj = X509_OBJECT_new())) {
			result = 0;
		} else {
			if (X509_STORE_CTX_get_by_subject(
				    ctx, X509_LU_X509,
				    X509_get_subject_name(err_cert), xobj)
				    > 0
			    && !X509_cmp(X509_OBJECT_get0_X509(xobj),
					 err_cert)) {
				if (err == X509_V_ERR_CERT_HAS_EXPIRED)
					mylog(LOG_INFO,
					      "Basic mode; Accepting "
					      "*expired* peer certificate "
					      "found in store.");
				else
					mylog(LOG_INFO,
					      "Basic mode; Accepting peer "
					      "certificate found in store.");

				result = 1;
				err = X509_V_OK;
				X509_STORE_CTX_set_error(ctx, err);
			} else {
				mylog(LOG_INFO,
				      "Basic mode; peer certificate NOT "
				      "in store, rejecting it!");
				err = X509_V_ERR_CERT_REJECTED;
				X509_STORE_CTX_set_error(ctx, err);

				link_add_untrusted(c->user_data,
						   X509_dup(err_cert));
			}
			X509_OBJECT_free(xobj);
		}
	}

	if (!result) {
		/* We have a verify error! Log it */
		mylog(LOG_ERROR, "SSL cert check failed at depth=%d: %s (%d)",
		      depth, X509_verify_cert_error_string(err), err);
	}

	return result;
}

static connection_t *_connection_new_SSL(char *dsthostname, char *dstport,
					 char *srchostname, char *srcport,
					 connection_ssl_options_t *ssl_options,
					 int timeout)
{
	connection_t *conn;
	log(LOG_DEBUG,
	    "_connection_new_SSL %d ssl_check_store: %s ssl_client_certfile: "
	    "%s ",
	    ssl_options->ssl_check_mode, ssl_options->ssl_check_store,
	    ssl_options->ssl_client_certfile);
	conn = connection_init(timeout, /*listen=*/0);
	if (!(conn->ssl_ctx_h = connection_create_ssl_context(
		      ssl_options->ssl_ciphers))) {
		mylog(LOG_ERROR, "SSL context initialization failed");
		return conn;
	}

	conn->cert = NULL;
	conn->ssl_check_mode = ssl_options->ssl_check_mode;

	switch (conn->ssl_check_mode) {
		struct stat st_buf;
	case SSL_CHECK_BASIC:
		if (!SSL_CTX_load_verify_locations(conn->ssl_ctx_h,
						   ssl_options->ssl_check_store,
						   NULL)) {
			mylog(LOG_ERROR,
			      "Can't assign check store to "
			      "SSL connection! Proceeding without!");
		}
		break;
	case SSL_CHECK_CA:
		if (!ssl_options->ssl_check_store) {
			if (SSL_CTX_set_default_verify_paths(conn->ssl_ctx_h)) {
				mylog(LOG_INFO,
				      "No SSL certificate check store "
				      "configured. "
				      "Default store will be used.");
				break;
			} else {
				mylog(LOG_ERROR,
				      "No SSL certificate check store "
				      "configured "
				      "and cannot use default store!");
				return conn;
			}
		}
		// Check if check_store is a file or directory
		if (stat(ssl_options->ssl_check_store, &st_buf) == 0) {
			if (st_buf.st_mode & S_IFDIR) {
				if (!SSL_CTX_load_verify_locations(
					    conn->ssl_ctx_h, NULL,
					    ssl_options->ssl_check_store)) {
					mylog(LOG_ERROR,
					      "Can't assign check store to "
					      "SSL connection!");
					return conn;
				}
				break;
			}
			if (st_buf.st_mode & S_IFREG) {
				if (!SSL_CTX_load_verify_locations(
					    conn->ssl_ctx_h,
					    ssl_options->ssl_check_store,
					    NULL)) {
					mylog(LOG_ERROR,
					      "Can't assign check store to "
					      "SSL connection!");
					return conn;
				}
				break;
			}
			mylog(LOG_ERROR,
			      "Specified SSL certificate check store is "
			      "neither "
			      "a file nor a directory.");
			return conn;
		}
		mylog(LOG_ERROR,
		      "Can't open SSL certificate check store! Check path "
		      "and permissions.");
		return conn;
	}

	switch (conn->ssl_check_mode) {
	case SSL_CHECK_NONE:
		SSL_CTX_set_verify(conn->ssl_ctx_h, SSL_VERIFY_NONE, NULL);
		break;
	case SSL_CHECK_BASIC:
		SSL_CTX_set_verify(conn->ssl_ctx_h, SSL_VERIFY_PEER,
				   bip_ssl_verify_callback);
		/* SSL_CTX_set_verify_depth(conn->ssl_ctx_h, 0); */
		break;
	case SSL_CHECK_CA:
		SSL_CTX_set_verify(conn->ssl_ctx_h, SSL_VERIFY_PEER,
				   bip_ssl_verify_callback);
		break;
	default:
		fatal("Unknown SSL cert check mode.");
	}

	if (ssl_options->ssl_client_certfile) {
		if (!SSL_CTX_use_certificate_chain_file(
			    conn->ssl_ctx_h, ssl_options->ssl_client_certfile))
			mylog(LOG_WARN, "SSL: Unable to load certificate file");
		else if (!SSL_CTX_use_PrivateKey_file(
				 conn->ssl_ctx_h,
				 ssl_options->ssl_client_certfile,
				 SSL_FILETYPE_PEM))
			mylog(LOG_WARN, "SSL: Unable to load key file");
		else
			mylog(LOG_INFO,
			      "SSL: using %s pem file as client SSL "
			      "certificate",
			      ssl_options->ssl_client_certfile);
	}

	conn->ssl_h = SSL_new(conn->ssl_ctx_h);
	if (conn->ssl_h == NULL) {
		mylog(LOG_ERROR, "Unable to allocate SSL structures");
		return conn;
	}
	SSL_set_connect_state(conn->ssl_h);

	/* Put our connection_t in the SSL object for the verify callback */
	SSL_set_ex_data(conn->ssl_h, ssl_cx_idx, conn);

	create_socket(dsthostname, dstport, srchostname, srcport, conn);

	return conn;
}
#endif

connection_t *connection_new(char *dsthostname, int dstport, char *srchostname,
			     int srcport, connection_ssl_options_t *options,
			     int timeout)
{
	char dstportbuf[20], srcportbuf[20], *tmp;
#ifndef HAVE_LIBSSL
	(void)options;
#endif
	/* TODO: allow litteral service name in the function interface */
	if (snprintf(dstportbuf, 20, "%d", dstport) >= 20)
		dstportbuf[19] = '\0';
	if (srcport) {
		if (snprintf(srcportbuf, 20, "%d", srcport) >= 20)
			srcportbuf[19] = '\0';
		tmp = srcportbuf;
	} else
		tmp = NULL;
#ifdef HAVE_LIBSSL
	if (options)
		return _connection_new_SSL(dsthostname, dstportbuf, srchostname,
					   tmp, options, timeout);
	else
#endif
		return _connection_new(dsthostname, dstportbuf, srchostname,
				       tmp, timeout);
}

int cn_is_listening(connection_t *cn)
{
	if (cn == NULL)
		return 0;
	else
		return cn->listening;
}

/* returns 1 if connection must be notified */
static int connection_timedout(connection_t *cn)
{
	if (cn_is_connected(cn) || !cn->timeout)
		return 0;

	if (!cn->connecting_data)
		fatal("connection_timedout called with no connecting_data!\n");

	if (time(NULL) - cn->connect_time > cn->timeout) {
		/* connect() completion timed out */
		close(cn->handle);
		cn->handle = -1;
		connect_trynext(cn);
		if (!cn_is_new(cn))
			return 1;
	}
	return 0;
}

static int socket_set_nonblock(int s)
{
	int flags;

	if ((flags = fcntl(s, F_GETFL, 0)) < 0) {
		mylog(LOG_ERROR, "Cannot set socket %d to non blocking : %s", s,
		      strerror(errno));
		return 0;
	}

	if (fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0) {
		mylog(LOG_ERROR, "Cannot set socket %d to non blocking : %s", s,
		      strerror(errno));
		return 0;
	}
	return 1;
}

static char *socket_ip(int fd, int remote, int *port)
{
	struct sockaddr addr;
	socklen_t addrlen;
	int err;

	*port = 0;
	if (fd <= 0)
		return NULL;

	addrlen = sizeof(addr);

	if (!remote) {
		/* getsockname every time to get IP version */
		err = getsockname(fd, (struct sockaddr *)&addr, &addrlen);
		if (err != 0) {
			mylog(LOG_ERROR, "in getsockname(%d): %s", fd,
			      strerror(errno));
			return NULL;
		}
	} else {
		err = getpeername(fd, &addr, &addrlen);
		if (err != 0) {
			mylog(LOG_ERROR, "in getsockname(%d): %s", fd,
			      strerror(errno));
			return NULL;
		}
	}
	return bip_ntop(&addr, port);
}

char *connection_localip(connection_t *cn)
{
	if (cn->handle <= 0)
		return NULL;
	int port = 0;
	return socket_ip(cn->handle, 0, &port);
}

char *connection_remoteip(connection_t *cn)
{
	if (cn->handle <= 0)
		return NULL;
	int port = 0;
	return socket_ip(cn->handle, 1, &port);
}

int connection_localport(connection_t *cn)
{
	if (cn->handle <= 0)
		return -1;
	int port = 0;
	free(socket_ip(cn->handle, 1, &port));
	return port;
}

int connection_remoteport(connection_t *cn)
{
	if (cn->handle <= 0)
		return -1;
	int port = 0;
	free(socket_ip(cn->handle, 0, &port));
	return port;
}
