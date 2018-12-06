/*
 * $Id: connection.h,v 1.40 2005/04/12 19:34:35 nohar Exp $
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

#ifndef CONNECTION_H
#define CONNECTION_H
#include "config.h"
#include "util.h"
#include "poller.h"
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>

#ifdef HAVE_LIBSSL
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#endif

#define CONN_BUFFER_SIZE 8192

#define CONN_OK 1
#define CONN_TIMEOUT 2
#define CONN_ERROR 3
#define CONN_INPROGRESS 4
#define CONN_DISCONN 5
#define CONN_EXCEPT 6
#define CONN_NEW 7
#define CONN_NEED_SSLIZE 8
#define CONN_UNTRUSTED 9
#define CONN_SSL_CONNECT 10
#define CONN_SSL_NEED_RETRY_WRITE 11
#define CONN_SSL_NEED_RETRY_READ 12

#define WRITE_OK 0
#define WRITE_ERROR -1
#define WRITE_KEEP -2

#define READ_OK 0
#define READ_ERROR -1

#define SSL_CHECK_NONE (0)
#define SSL_CHECK_BASIC (1)
#define SSL_CHECK_CA (2)

typedef struct {
	char *ciphers;
	char *dh_file;
	char *cert_pem_file;
} listener_ssl_options_t;
void listener_ssl_options_init(listener_ssl_options_t* options);

typedef struct {
	// Ciphers to allow when connecting to an irc network.
	char *ssl_ciphers;
	// SSL check mode when connection to an irc network.
	int ssl_check_mode;
	// SSL store to use to trust CAs. Defaults to system CAs.
	char *ssl_check_store;
	// SSL client certificate to use.
	char *ssl_client_certfile;
} connection_ssl_options_t;
void connection_ssl_options_init(connection_ssl_options_t* options);

struct connecting_data;
typedef struct connection {
	int anti_flood;
	unsigned long lasttoken;
	unsigned token;
	int handle;
	int connected;
	int listening;
	int ssl_client;
	time_t connect_time;
	time_t timeout;
	char *incoming;
	unsigned incoming_end;
	list_t *outgoing;
	char *partial;
	list_t *incoming_lines;
	void *user_data;
	struct connecting_data *connecting_data;
#ifdef HAVE_LIBSSL
	SSL_CTX *ssl_ctx_h;
	SSL *ssl_h;
	X509 *cert;
#endif
	int ssl_check_mode;
	char *localip, *remoteip;
	uint16_t localport, remoteport;
} connection_t;

#define LISTEN_OK 1
#define LISTEN_ERROR 2

typedef struct listener {
	int anti_flood;
	int state;
	int handle;
	list_t accepted_connections;
	char *localip;
	void *user_data;
	time_t timeout;
	uint16_t localport;
#ifdef HAVE_LIBSSL
	SSL_CTX* ssl_context;
#endif
} listener_t;

connection_t *connection_new(char *dsthostname, int dstport, char *srchostname,
			     int srcport, connection_ssl_options_t *ssl_options,
			     int timeout);
listener_t *listener_new(char *hostname, int port,
			 listener_ssl_options_t *ssl_options);
void listener_init(listener_t *listener, char *hostname, int port,
		   listener_ssl_options_t *options);
connection_t *accept_new(listener_t *cn);
void connection_free(connection_t *cn);
void connection_close(connection_t *cn);

void write_line(connection_t *cn, char *line);
void write_lines(connection_t *cn, list_t *lines);
void write_line_fast(connection_t *cn, char *line);
list_t *read_lines(connection_t *cn, int *error);
void wait_event(list_t *listeners_list, list_t *cn_list, int *msec);

int cn_is_connected(connection_t *cn);
int cn_is_listening(connection_t *cn);

int connection_localport(connection_t *cn);
int connection_remoteport(connection_t *cn);
char *connection_localip(connection_t *cn);
char *connection_remoteip(connection_t *cn);

poller_t* global_poller();

void connection_ssl_initialize();

#endif
