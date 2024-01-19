#include <config.h>

#include "quic_test_util.h"
#include <time.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/wait.h>

#include <wget.h> 
/**
 * This function will initialise the QUIC server and 
 * do a fork of the process and child process will stay here 
 * and the parent process will return to the actual testing code.
*/

#define PRIO "NORMAL:-VERS-ALL:+VERS-TLS1.3:" \
  "-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM:" \
  "-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1:" \
  "%DISABLE_TLS13_COMPAT_MODE"

#define MAX_TP_SIZE 128
#define MAX_EVENTS 64

/* Utils related to setting a QUIC Server */
int
resolve_and_bind (const char *host, const char *port,
                struct sockaddr *local_addr, size_t *local_addrlen)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int ret, fd;

    memset (&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags  =  AI_PASSIVE;

    ret = getaddrinfo (host, port, &hints, &result);
    if (ret != 0)
    return -1;

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        fd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1)
        continue;

        if (bind (fd, rp->ai_addr, rp->ai_addrlen) == 0)
        {
            *local_addrlen = rp->ai_addrlen;
            memcpy(local_addr, rp->ai_addr, rp->ai_addrlen);
            break;
        }

        close (fd);
    }

    freeaddrinfo(result);

    if (rp == NULL)
        return -1;

    return fd;
}

gnutls_certificate_credentials_t *
create_tls_server_credentials (const char *key_file, const char *cert_file)
{
    gnutls_certificate_credentials_t *cred = wget_malloc(sizeof(gnutls_certificate_credentials_t));
    int ret;

    ret = gnutls_certificate_allocate_credentials (cred);
    if (ret < 0) {
        return NULL;
    }

    ret = gnutls_certificate_set_x509_key_file (*cred, cert_file, key_file,
                                              GNUTLS_X509_FMT_PEM);
    if (ret < 0) {
        return NULL;
    }
    return cred;
}

uint64_t
timestamp (void)
{
    struct timespec tp;
    if (clock_gettime (CLOCK_MONOTONIC, &tp) < 0)
    return 0;
    return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

void 
log_printf(void *user_data, const char *fmt, ...)
{
	va_list ap;
	(void) user_data;

	va_start(ap, fmt);
	wget_debug_vprintf(fmt, ap);
	va_end(ap);
	wget_debug_printf("\n");
}

ssize_t
recv_packet (int fd, uint8_t *data, size_t data_size,
             struct sockaddr *remote_addr, size_t *remote_addrlen)
{
    struct iovec iov;
    iov.iov_base = data;
    iov.iov_len = data_size;

    struct msghdr msg;
    memset (&msg, 0, sizeof(msg));

    msg.msg_name = remote_addr;
    msg.msg_namelen = *remote_addrlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ssize_t ret;

    do
        ret = recvmsg (fd, &msg, MSG_DONTWAIT);
    while (ret < 0 && errno == EINTR);

    *remote_addrlen = msg.msg_namelen;

    return ret;
}

wget_quic_test_connection *
find_connection(wget_quic_test_server *server, const uint8_t *dcid, size_t dcid_size)
{
    for (int i = 0 ; i < MAX_SERVER_CONNECTIONS ; i++)
	{
		wget_quic_test_connection *connection = server->connections[i];
        if (connection) {
            ngtcp2_conn *conn = connection->conn;
            size_t n_scids = ngtcp2_conn_get_num_scid(conn);
            ngtcp2_cid *scids = NULL;

            scids = wget_malloc(sizeof(ngtcp2_cid)*n_scids);
            if (!scids) {
                return NULL;
            }

            n_scids = ngtcp2_conn_get_scid(conn, scids);
            for (size_t i = 0; i < n_scids; i++)
            {
                if (dcid_size == scids[i].datalen &&
                    memcmp(dcid, scids[i].data, dcid_size) == 0) {
                    return connection;
                }
            }
        }
	}
	return NULL;
}

int
create_tls_server_session (wget_quic_test_server **server ,wget_quic_test_connection **connection ,const char *key_file, const char *cert_file)
{
    gnutls_session_t session;
    gnutls_certificate_credentials_t cred = wget_malloc(sizeof(gnutls_certificate_credentials_t));
    wget_quic_test_server *serv = *server;
    wget_quic_test_connection *conn = *connection;
    int ret;

    gnutls_global_init();

    ret = gnutls_init (&session,
                        GNUTLS_SERVER |
                        GNUTLS_ENABLE_EARLY_DATA |
                        GNUTLS_NO_END_OF_EARLY_DATA);
    if (ret < 0) {
        wget_error_printf("gnutls_init: %s",
                    gnutls_strerror (ret));
        return -1;
    }

    gnutls_certificate_allocate_credentials(&cred);
    gnutls_certificate_set_x509_system_trust(cred);
    ret = gnutls_certificate_set_x509_key_file (cred, cert_file, key_file,
                                            GNUTLS_X509_FMT_PEM);

    ret = gnutls_priority_set_direct (session, PRIO, NULL);
    if (ret < 0 && session) {
        wget_error_printf("gnutls_priority_set_direct: %s",
                    gnutls_strerror (ret));
        return -1;
    }

    ret = gnutls_credentials_set (session,
                                GNUTLS_CRD_CERTIFICATE,
                                cred);
    if (ret < 0) {
        wget_error_printf("gnutls_credentials_set: %s",
                    gnutls_strerror (ret));
        return -1;
    }
    serv->cred = &cred;
    
    conn->session = session;
    return 0;
}

wget_quic_stream *
connection_find_stream (wget_quic_test_connection *connection, int64_t stream_id)
{
    for (int i = 0 ; i < MAX_SERVER_STREAMS ; i++)
    {
        wget_quic_stream *stream = connection->streams[i];
        if (!stream) {
            continue;
        }
        if (wget_quic_stream_get_stream_id(stream) == stream_id) {
            return stream;
        }
    }
    return NULL;
}

void
stream_mark_acked (wget_quic_stream *stream, size_t offset)
{
  	while (stream && wget_quic_stream_get_ack_offset(stream) < offset) {
		wget_byte *head  = (wget_byte *)wget_queue_peek_transmitted_node(wget_quic_stream_get_buffer(stream));

		if (wget_quic_stream_get_ack_offset(stream) + wget_byte_get_size (head) > offset)
			break;

		wget_quic_stream_set_ack_offset(stream, (wget_quic_stream_get_ack_offset(stream) + wget_byte_get_size (head)));
		wget_queue_dequeue_transmitted_node(wget_quic_stream_get_buffer(stream));
    }
}

static int
acked_stream_data_offset_cb(ngtcp2_conn *conn __attribute__((unused)),
							int64_t stream_id, uint64_t offset,
							uint64_t datalen,
							void *user_data,
							void *stream_user_data __attribute__((unused)))
{
	wget_quic_test_connection *connection = user_data;
	wget_quic_stream *stream = connection_find_stream(connection, stream_id);
	if (stream)
		stream_mark_acked(stream, offset + datalen);
	return 0;
}

static int
recv_stream_data_cb(ngtcp2_conn *conn __attribute__((unused)),
					uint32_t flags __attribute__((unused)),
					int64_t stream_id,
					uint64_t offset __attribute__((unused)),
					const uint8_t *data, size_t datalen,
					void *user_data,
					void *stream_user_data __attribute__((unused)))
{
    wget_debug_printf("receiving %zu bytes from stream #%zd\n", datalen, stream_id);
	wget_quic_test_connection *connection = user_data;
	wget_quic_stream *stream = connection_find_stream(connection, stream_id);

	if (stream) {
		int ret = wget_quic_stream_push(stream, (const char *)data, datalen, REQUEST_BYTE);
		if (ret < 0)
			return ret;
        return 0;
	}

	return -1;
}

static int
stream_open_cb(ngtcp2_conn *conn __attribute__((unused)),
			   int64_t stream_id, void *user_data)
{
    wget_quic_test_connection *connection = user_data;
    wget_quic_stream *stream = wget_quic_set_stream (stream_id);
    if (stream) {
        for (int i = 0 ; i < MAX_SERVER_STREAMS ; i++) {
            if (!connection->streams[i]) {
                connection->streams[i] = stream;
                return 0;
            }
        }
    }
    return -1;
}

static void
rand_cb(uint8_t *dest, size_t destlen,
		const ngtcp2_rand_ctx *rand_ctx __attribute__((unused)))
{
	int ret;

	ret = gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
	if (ret < 0)
		wget_debug_printf("gnutls_rnd: %s\n", gnutls_strerror(ret));
}

int
get_random_cid (ngtcp2_cid *cid)
{
    // const uint8_t *buf = wget_malloc(sizeof(uint8_t)*NGTCP2_MAX_CIDLEN);
    // if (!buf) {
    //     wget_error_printf ("wget_malloc\n");
    //     return -1;
    // }
    // size_t buff_size = sizeof(buf);
    uint8_t buf[NGTCP2_MAX_CIDLEN];
    int ret;

    ret = gnutls_rnd (GNUTLS_RND_RANDOM, buf, sizeof(buf));
    if (ret < 0)
    {
        wget_error_printf ("gnutls_rnd: %s\n", gnutls_strerror (ret));
        return -1;
    }
    ngtcp2_cid_init (cid, buf, sizeof(buf));
    return 0;
}

static int
get_new_connection_id_cb(ngtcp2_conn *conn __attribute__((unused)),
						 ngtcp2_cid *cid, uint8_t *token,
						 size_t cidlen,
						 void *user_data __attribute__((unused)))
{
	int ret;

	ret = gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen);
	if (ret < 0)
		return NGTCP2_ERR_CALLBACK_FAILURE;

	cid->datalen = cidlen;

	ret = gnutls_rnd(GNUTLS_RND_RANDOM, token, NGTCP2_STATELESS_RESET_TOKENLEN);
	if (ret < 0)
		return NGTCP2_ERR_CALLBACK_FAILURE;

	return 0;
}

static const ngtcp2_callbacks callbacks =
{
    /* Use the default implementation from ngtcp2_crypto */
    .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,

    .acked_stream_data_offset = acked_stream_data_offset_cb,
    .recv_stream_data = recv_stream_data_cb,
    .stream_open = stream_open_cb,
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb,
};

void
connection_set_local_addr (wget_quic_test_connection *connection,
                           struct sockaddr *local_addr,
                           size_t local_addrlen)
{
    memcpy (&connection->local_addr, local_addr, local_addrlen);
    connection->local_addrlen = local_addrlen;
}

void
connection_set_remote_addr (wget_quic_test_connection *connection,
                           struct sockaddr *remote_addr,
                           size_t remote_addrlen)
{
    memcpy (&connection->remote_addr, remote_addr, remote_addrlen);
    connection->remote_addrlen = remote_addrlen;
}

static wget_quic_test_connection *
accept_connection(wget_quic_test_server *server,
				  struct sockaddr *remote_addr, size_t remote_addrlen,
				  const uint8_t *data, size_t data_size, const char *key_file, const char *cert_file)
{
	ngtcp2_pkt_hd header;
	int ret;

	ret = ngtcp2_accept(&header, data, data_size);
	if (ret < 0)
		return NULL;

	wget_quic_test_connection *connection = wget_malloc(sizeof(wget_quic_test_connection));
    if (!connection)
		return NULL;

    // connection->session = session;
    connection->socket_fd = server->socket_fd;

    ret = create_tls_server_session(&server, &connection, key_file, cert_file);
	if (ret < 0) {
        wget_error_printf("Error in create_tls_server_session\n");
		return NULL;
    }

	ngtcp2_path path =
    {
        .local = {
            .addrlen = server->local_addrlen,
            .addr = (struct sockaddr *)&server->local_addr
        },
        .remote = {
            .addrlen = remote_addrlen, 
            .addr = (struct sockaddr *)remote_addr
        }
    };

	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);
	params.initial_max_streams_uni = 3;
	params.initial_max_streams_bidi = 3;
	params.initial_max_stream_data_bidi_local = 128 * 1024;
	params.initial_max_stream_data_bidi_remote = 128 * 1024;
	params.initial_max_data = 1024 * 1024;
	memcpy(&params.original_dcid, &header.dcid, sizeof(params.original_dcid));
    params.original_dcid_present = 1;

	ngtcp2_conn *conn = NULL;
    ngtcp2_cid scid;
	if (get_random_cid(&scid) < 0) {
		return NULL;
    }

	ret = ngtcp2_conn_server_new(&conn,
								 &header.scid,
								 &scid,
								 &path,
								 header.version,
								 &callbacks,
								 &server->settings,
								 &params,
								 NULL,
								 connection);
	if (ret < 0)
	{
		wget_debug_printf("ngtcp2_conn_server_new: %s",
				ngtcp2_strerror(ret));
		return NULL;
	}

	connection->conn = conn;
	connection_set_local_addr(connection,
							  (struct sockaddr *)&server->local_addr,
							  server->local_addrlen);
	connection_set_remote_addr(connection,
							   (struct sockaddr *)remote_addr,
							   remote_addrlen);

    /* But the connection here is not freed. Keep this in mind :) */
	return connection;
}

static int
handshake_secret_func (gnutls_session_t session,
                       gnutls_record_encryption_level_t glevel,
                       const void *secret_read, const void *secret_write,
                       size_t secret_size)
{
    ngtcp2_conn *conn = gnutls_session_get_ptr (session);
    ngtcp2_encryption_level level =
    ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level (glevel);
    uint8_t key[64], iv[64], hp_key[64];

    if (secret_read &&
        ngtcp2_crypto_derive_and_install_rx_key (conn,
                                                key, iv, hp_key, level,
                                                secret_read, secret_size) < 0)
        return -1;

    if (secret_write &&
        ngtcp2_crypto_derive_and_install_tx_key (conn,
                                                key, iv, hp_key, level,
                                                secret_write, secret_size) < 0)
        return -1;

    return 0;
}

static int
handshake_read_func (gnutls_session_t session,
                     gnutls_record_encryption_level_t glevel,
                     gnutls_handshake_description_t htype,
                     const void *data, size_t data_size)
{
    if (htype == GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC)
        return 0;

    ngtcp2_conn *conn = gnutls_session_get_ptr (session);
    ngtcp2_encryption_level level =
    ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level (glevel);

    int ret;

    ret = ngtcp2_conn_submit_crypto_data (conn, level, data, data_size);
    if (ret < 0)
    {
        wget_error_printf("ngtcp2_conn_submit_crypto_data: %s",
                ngtcp2_strerror (ret));
        return -1;
    }

    return 0;
}

static int
alert_read_func (gnutls_session_t session __attribute__((unused)),
                 gnutls_record_encryption_level_t level __attribute__((unused)),
                 gnutls_alert_level_t alert_level __attribute__((unused)),
                 gnutls_alert_description_t alert_desc __attribute__((unused)))
{
  return 0;
}

static int
tp_recv_func (gnutls_session_t session, const uint8_t *data, size_t data_size)
{
    ngtcp2_conn *conn = gnutls_session_get_ptr (session);
    int ret;

    ret = ngtcp2_conn_decode_and_set_remote_transport_params(conn,data, data_size);
    if (ret < 0)
    {
        wget_error_printf("ngtcp2_decode_transport_params: %s\n", ngtcp2_strerror (ret));
        return -1;
    }

    return 0;
}

static int 
tp_send_func(gnutls_session_t session, gnutls_buffer_t extdata)
{
	int ret;
	uint8_t buf[MAX_TP_SIZE];
	ngtcp2_conn *conn = gnutls_session_get_ptr(session);
	const ngtcp2_transport_params *params = ngtcp2_conn_get_local_transport_params(conn);
	ngtcp2_ssize n_encoded =
		ngtcp2_transport_params_encode(buf, sizeof(buf), params);

	if (n_encoded < 0) {
		wget_debug_printf("ngtcp2_encode_transport_params: %s", ngtcp2_strerror (n_encoded));
		return -1;
	}

	ret = gnutls_buffer_append_data(extdata, buf, n_encoded);
	if (ret < 0) {
		wget_debug_printf("gnutls_buffer_append_data failed: %s", gnutls_strerror (ret));
		return -1;
	}

	return n_encoded;
}

int
setup_gnutls_for_quic (gnutls_session_t session, ngtcp2_conn *conn)
{
    int ret;

    gnutls_handshake_set_secret_function (session, handshake_secret_func);
    gnutls_handshake_set_read_function (session, handshake_read_func);
    gnutls_alert_set_read_function (session, alert_read_func);

    ret = gnutls_session_ext_register (session, "QUIC Transport Parameters",
                                        NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1,
                                        GNUTLS_EXT_TLS,
                                        tp_recv_func, tp_send_func,
                                        NULL, NULL, NULL,
                                        GNUTLS_EXT_FLAG_TLS |
                                        GNUTLS_EXT_FLAG_CLIENT_HELLO |
                                        GNUTLS_EXT_FLAG_EE);
    if (ret < 0)
        return ret;

    gnutls_datum_t alpn = { (unsigned char *)"h3", sizeof("h3")-1};
    gnutls_alpn_set_protocols(session, &alpn, 1, 0);

    gnutls_server_name_set (session, GNUTLS_NAME_DNS, "localhost",
                            sizeof("localhost")-1);

    ngtcp2_conn_set_tls_native_handle (conn, session);
    gnutls_session_set_ptr (session, conn);

    return 0;
}

int
connection_start (wget_quic_test_connection *connection)
{

    if (!connection->session || !connection->conn) {
        return -1;
    }

    setup_gnutls_for_quic (connection->session, connection->conn);

    connection->timer_fd =  timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (connection->timer_fd < 0)
    {
        wget_error_printf("timerfd_create: %s", wget_strerror(errno));
        return -1;
    }

    return 0;
}

static int
handle_incoming(wget_quic_test_server *server, const char *key_file, const char *cert_file)
{
	uint8_t buf[BUF_SIZE];

	for (;;)
	{
		ssize_t n_read;
		struct sockaddr_storage remote_addr;
		size_t remote_addrlen = sizeof(remote_addr);
		int ret;

		n_read = recv_packet(server->socket_fd, buf, sizeof(buf),
							 (struct sockaddr *)&remote_addr,
							 &remote_addrlen);
		if (n_read < 0)
		{
			if (n_read != EAGAIN && n_read != EWOULDBLOCK)
				return 0;
			wget_error_printf("recv_packet: %s\n", strerror(errno));
			return -1;
		}

		ngtcp2_version_cid version;

		ret = ngtcp2_pkt_decode_version_cid(&version,
											buf, n_read,
											NGTCP2_MAX_CIDLEN);
		if (ret < 0)
		{
			wget_error_printf("ngtcp2_pkt_decode_version_cid: %s",
					  wget_strerror(ret));
			return -1;
		}

		/* Find any existing connection by DCID */
		wget_quic_test_connection *connection = find_connection(server, version.dcid, version.dcidlen);
		if (!connection)
		{
			connection = accept_connection(server,
										   (struct sockaddr *)&remote_addr,
										   remote_addrlen,
										   buf, n_read, key_file, cert_file);
			if (!connection)
				return -1;

            bool server_connection_availabe = false;
            for (int i = 0 ; i < MAX_SERVER_CONNECTIONS ; i++) {
                if (server->connections[i] == NULL) {
                    server->connections[i] = connection;
                    server_connection_availabe = true;
                }
            }

            if (!server_connection_availabe) {
                return -1;
            }

			ret = connection_start(connection);
			if (ret < 0)
				return -1;

			struct epoll_event ev;
			ev.events = EPOLLIN | EPOLLET;
			ev.data.fd = connection->timer_fd;
			ret = epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev);
			if (ret < 0)
			{
				wget_error_printf("epoll_ctl: %s", wget_strerror(ret));
				return -1;
			}
		}

		ngtcp2_conn *conn = connection->conn;

		ngtcp2_path path;
		memcpy(&path, ngtcp2_conn_get_path(conn), sizeof(path));
		path.remote.addrlen = remote_addrlen;
		path.remote.addr = (struct sockaddr *)&remote_addr;

		ngtcp2_pkt_info pi;
		memset(&pi, 0, sizeof(pi));

		ret = ngtcp2_conn_read_pkt(conn, &path, &pi, buf, n_read, timestamp());
		if (ret < 0)
		{
			wget_error_printf("ngtcp2_conn_read_pkt: %s",
					  ngtcp2_strerror(ret));

			/* Remove the connection upon read error */
            for (int i = 0 ; i < MAX_SERVER_CONNECTIONS ; i++) {
                if (server->connections[i] == connection) {
                    server->connections[i] = NULL;
                }
            }
			ret = epoll_ctl(server->epoll_fd, EPOLL_CTL_DEL,
							connection->timer_fd,
							NULL);
			if (ret < 0)
			{
				wget_error_printf("epoll_ctl: %s",
						  wget_strerror(errno));
				return -1;
			}
			connection->socket_fd = -1;
            /* Here freeing of all the internal components of the wget is not taken into consideration */
			wget_free(connection);
		}
	}
	return 0;
}

ssize_t
send_packet (int fd, const uint8_t *data, size_t data_size,
             struct sockaddr *remote_addr, size_t remote_addrlen)
{
    struct iovec iov;
    iov.iov_base = (void *)data;
    iov.iov_len = data_size;

    struct msghdr msg;
    memset (&msg, 0, sizeof(msg));
    msg.msg_name = remote_addr;
    msg.msg_namelen = remote_addrlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ssize_t ret;

    do
        ret = sendmsg (fd, &msg, MSG_DONTWAIT);
    while (ret < 0 && errno == EINTR);
    return ret;
}

static int
write_to_stream (wget_quic_test_connection *connection, wget_quic_stream *stream)
{
    uint8_t buf[BUF_SIZE];

    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);

    ngtcp2_pkt_info pi;
    uint64_t ts = timestamp ();

    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

    for (;;)
    {
        ngtcp2_vec datav;
        int64_t stream_id;

        if (stream) {
            wget_byte *byte = wget_queue_peek_untransmitted_node(wget_quic_stream_get_buffer(stream));
            if (!byte)
			    break;
            datav.base = wget_byte_get_data(byte);
            datav.len = wget_byte_get_size(byte);
            stream_id = wget_quic_stream_get_stream_id(stream);
            if (datav.len == 0) {
                /* No stream data to be sent */
                stream_id = -1;
                flags &= ~NGTCP2_WRITE_STREAM_FLAG_MORE;
            }
            else {
                stream_id = wget_quic_stream_get_stream_id(stream);
            }
        }
        else {
            datav.base = NULL;
            datav.len = 0;
            stream_id = -1;
        }

        ngtcp2_ssize n_read, n_written;

        n_written = ngtcp2_conn_writev_stream (connection->conn, &ps.path, &pi,
                            buf, sizeof(buf),
                            &n_read,
                            flags,
                            stream_id,
                            &datav, 1,
                            ts);
        if (n_written < 0)
        {
            if (n_written == NGTCP2_ERR_WRITE_MORE) {
                wget_quic_stream_set_sent_offset(stream, (wget_quic_stream_get_sent_offset(stream)+n_read));
                continue;
            }
            wget_error_printf ("ngtcp2_conn_writev_stream: %s",
                        ngtcp2_strerror ((int)n_written));
            return -1;
        }

        if (n_written == 0)
            return 0;

        if (stream && n_read > 0)
            wget_quic_stream_set_sent_offset(stream, (wget_quic_stream_get_sent_offset(stream)+n_read));

        int ret;

        ret = send_packet (connection->socket_fd, buf, n_written,
                            (struct sockaddr *)&connection->remote_addr,
                            connection->remote_addrlen);
        if (ret < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            wget_error_printf ("send_packet: %s", wget_strerror (errno));
            return -1;
        }

        /* No stream data to be sent */
        if (stream && datav.len == 0)
            break;
    }

    return 0;
}

int
connection_write (wget_quic_test_connection *connection)
{
    int ret;

    for (int i = 0 ; i < MAX_SERVER_STREAMS ; i++) {
        ret = write_to_stream (connection, connection->streams[i]);
        if (ret < 0)
            return -1;
    }

    ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry (connection->conn);
    ngtcp2_tstamp now = timestamp ();
    struct itimerspec it;
    memset (&it, 0, sizeof (it));

    ret = timerfd_settime (connection->timer_fd, 0, &it, NULL);
    if (ret < 0)
    {
        wget_error_printf ("timerfd_settime: %s", wget_strerror (errno));
        return -1;
    }
    if (expiry < now)
    {
        it.it_value.tv_sec = 0;
        it.it_value.tv_nsec = 1;
    }
    else
    {
        it.it_value.tv_sec = (expiry - now) / NGTCP2_SECONDS;
        it.it_value.tv_nsec = ((expiry - now) % NGTCP2_SECONDS) / NGTCP2_NANOSECONDS;
    }
    ret = timerfd_settime (connection->timer_fd, 0, &it, NULL);
    if (ret < 0)
    {
        wget_error_printf ("timerfd_settime: %s", wget_strerror (errno));
        return -1;
    }

    return 0;
}

/* Actual function to start the QUIC server. */
void start_quic_server(const char *key_file, const char *cert_file)
{
    /* Initialising the server. */
    wget_quic_test_server *server = wget_malloc(sizeof(wget_quic_test_server));
    server->cred = NULL;
    server->local_addrlen = sizeof(struct sockaddr_storage);
    server->epoll_fd = -1;
    for (int i = 0 ; i < MAX_SERVER_CONNECTIONS ; i++){
        server->connections[i] = NULL;
    }

    /* Create a server socket */
    int fd = -1;
    const char *hostname = "localhost";
    const char *portname = "5556";
    fd = resolve_and_bind(hostname, portname, (struct sockaddr *)&server->local_addr, &server->local_addrlen);
    if (fd < 0) {
        wget_error_printf("resolve_and_bind error\n");
        return;
    }

    server->socket_fd = fd;
    // gnutls_certificate_credentials_t *cred = NULL;
    // cred = create_tls_server_credentials (key_file, cert_file);
    // if (!cred) {
    //     wget_error_printf("create_tls_server_credentials error\n");
    //     return;
    // }

    // server->cred = cred;
    server->cred = NULL;
    ngtcp2_settings_default(&server->settings);
    server->settings.initial_ts = timestamp();
    // server->settings.log_printf = log_printf(); //Error of incorrect signature.

    /* Starting the server. */
    /* This part below will go inside the fork if statement.*/
    server->epoll_fd = epoll_create1 (0);
    if (server->epoll_fd < 0) {
        /* Some return value will have to be given to this function */
        wget_error_printf("epoll_create1: %s", wget_strerror(errno));
        return;
    }

    struct epoll_event ev;

    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.fd = server->socket_fd;
    if (epoll_ctl (server->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) < 0) {
        wget_error_printf("epoll_ctl: %s", wget_strerror(errno));
        return;
    }

    for (;;) {
        struct epoll_event events[MAX_EVENTS];
        int nfds;

        nfds = epoll_wait (server->epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            /* Some return value will have to be given to this function */
            wget_error_printf("epoll_wait: %s", wget_strerror(errno));
            return;
        }

        for (int n = 0 ; n < nfds ; n++) {

            int ret;
            if (events[n].data.fd == server->socket_fd) {
                if (events[n].events & EPOLLIN) {
                    (void)handle_incoming(server, key_file, cert_file);
                }

                if (events[n].events & EPOLLOUT) {
                    for (int i = 0 ; i < MAX_SERVER_CONNECTIONS ; i++)
                    {
                        wget_quic_test_connection *connection = server->connections[i];
                        if (connection)
                            (void)connection_write(connection);
                    }
                }
            } else {
                for (int i = 0 ; i < MAX_SERVER_CONNECTIONS ; i++) {
                    wget_quic_test_connection *connection = server->connections[i];
                    if (connection && events[n].data.fd == connection->timer_fd) {
                        ngtcp2_conn *conn = connection->conn;
                        ret = ngtcp2_conn_handle_expiry(conn, timestamp());
                        if (ret < 0)
                        {
                            wget_error_printf("ngtcp2_conn_handle_expiry: %s",
                                    ngtcp2_strerror(ret));
                            continue;
                        }

                        (void)connection_write(connection);
                    }
                }
            }
        }
    }
}

void start_quic_test_server(const char *key_file, const char *cert_file) {
    pid_t child_pid;

    child_pid = fork();
    if (child_pid < 0) { 
        wget_error_printf("fork failed\n");
        return;
    }
    else if (child_pid == 0) {
        start_quic_server(key_file, cert_file);
        exit(1);
    }
    else {
        return;
    }
}