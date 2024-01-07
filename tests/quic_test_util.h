#ifndef WGETQUIC_TEST_UTIL_H
#define WGETQUIC_TEST_UTIL_H

#include <sys/socket.h>
#include <ngtcp2/ngtcp2.h>
#include <gnutls/gnutls.h>

#include <wget.h>

#define MAX_SERVER_CONNECTIONS 10
#define MAX_SERVER_STREAMS 10
#define BUF_SIZE 1280

typedef struct wget_quic_test_connection_t {
    gnutls_session_t session;
    ngtcp2_conn *conn;
    int socket_fd;
    int timer_fd;
    struct sockaddr_storage local_addr;
    size_t local_addrlen;
    struct sockaddr_storage remote_addr;
    size_t remote_addrlen;
    wget_quic_stream *streams[MAX_SERVER_STREAMS];
    bool is_closed;
}wget_quic_test_connection;

typedef struct wget_quic_test_server_t {
    int epoll_fd;
    int socket_fd;
    struct sockaddr_storage local_addr;
    size_t local_addrlen;
    wget_quic_test_connection *connections[MAX_SERVER_CONNECTIONS];
    gnutls_certificate_credentials_t *cred;
    ngtcp2_settings settings;
    ngtcp2_cid scid;
}wget_quic_test_server;

void start_quic_test_server(const char *key_file, const char *cert_file);
void start_quic_server(const char *key_file, const char *cert_file);
#endif //WGETQUIC_TEST_UTIL_H
