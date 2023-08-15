#include <config.h>

#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <c-ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#ifdef WITH_LIBNGTCP2
#include <ngtcp2/ngtcp2.h>
#endif
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#if ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
# include <sys/ioctl.h>
#else
# include <fcntl.h>
#endif

#include <wget.h>
#include "private.h"
#include "net.h"


#define BUF_SIZE 1280
#define MAX_EVENTS 64

static struct wget_quic_st global_quic = {
	.sockfd = -1,
	.connect_timeout = -1,
	.family = AF_UNSPEC,
	.preferred_family = AF_UNSPEC,
	.streams = {NULL},
};

uint64_t timestamp (void);
void quic_stream_mark_acked (wget_quic_stream *stream, size_t offset);
ssize_t send_packet(int fd, const uint8_t *data, size_t data_size,
		    struct sockaddr *remote_addr, size_t remote_addrlen);
int get_random_cid (ngtcp2_cid *cid);
ssize_t recv_packet(int fd, uint8_t *data, size_t data_size,
		    struct sockaddr *remote_addr, size_t *remote_addrlen);
int quic_handshake(wget_quic* quic);
static void _set_async(int fd);
void quic_stream_mark_sent(wget_quic_stream *stream, ngtcp2_ssize offset);
wget_byte *quic_stream_peek_data(wget_quic_stream *stream);
void log_printf(void *user_data, const char *fmt, ...);
wget_quic_stream *stream_new(int64_t id);
static int handshake_completed(wget_quic *quic);

static inline void print_error_host(const char *msg, const char *host)
{
	wget_error_printf("%s (hostname='%s', errno=%d)\n",
		msg, host, errno);
}

void log_printf(void *user_data, const char *fmt, ...)
{
	va_list ap;
	(void) user_data;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#ifdef WITH_LIBNGTCP2
wget_quic *wget_quic_init(void)
{
	wget_quic *quic = wget_malloc(sizeof(wget_quic));
	if (quic) {
		*quic = global_quic;
	} else {
		return NULL;
	}

	quic->local = wget_malloc(sizeof(info_addr));
	if (!quic->local) {
		xfree(quic);
		return NULL;
	} else {
		quic->local->addr = wget_malloc(sizeof(struct sockaddr));
	}

	quic->remote = wget_malloc(sizeof(info_addr));
	if (!quic->remote) {
		xfree(quic);
		return NULL;
	} else {
		quic->remote->addr = wget_malloc(sizeof(struct sockaddr));
	}

	return quic;
}
#else
wget_quic *wget_quic_init(void)
{
	return NULL;
}
#endif

#ifdef WITH_LIBNGTCP2
void wget_quic_deinit (wget_quic **_quic)
{
	wget_quic *quic = *_quic;

	if (quic){
		if (quic->ssl_hostname){
			xfree(quic->ssl_hostname);
		}

		xfree(quic->local->addr);
		xfree(quic->remote->addr);
		xfree(quic->local);
		xfree(quic->remote);
		xfree(quic);
	}

	quic = NULL;
}
#else
void wget_quic_deinit (wget_quic **_quic)
{
	return;
}
#endif

#ifdef WITH_LIBNGTCP2
void 
wget_quic_set_connect_timeout(wget_quic *quic, int timeout)
{
	(quic ? quic : &global_quic)->connect_timeout = timeout;
}
#else
void 
wget_quic_set_connect_timeout(wget_quic *quic, int timeout)
{
	return;
}
#endif

#ifdef WITH_LIBNGTCP2
void 
wget_quic_set_ssl_hostname(wget_quic *quic, const char *hostname)
{
	if (!quic)
		quic = &global_quic;

	xfree(quic->ssl_hostname);
	quic->ssl_hostname = wget_strdup(hostname);
}
#else
void 
wget_quic_set_ssl_hostname(wget_quic *quic, const char *hostname)
{
	return;
}
#endif

/*

Structs present : 

Struct similar to GBytes.
A node of this struct is pushed to the GQueue which is present in the struct 
Stream. This struct Stream is appended in the Glist present in the struct 
Connection. 

Implementations : 
1. Standard Implementation of Bytes, Generic Queue and Generic List.
2. All the standard functions for accessing all these structures.

*/

//Bytes Implementation.
//Apperently as per my observation, there is a ref count in the wget_byte.
//This should handle duplicate data. Not yet handled in the implementation.

/* Helper Function for Setting quic_connect */
uint64_t
timestamp (void)
{
  struct timespec tp;

  if (clock_gettime (CLOCK_MONOTONIC, &tp) < 0)
    return 0;

  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

/* Callback functions for ngtcp2 */

static void
rand_cb (uint8_t *dest, size_t destlen,
	 const ngtcp2_rand_ctx *rand_ctx __attribute__((unused)))
{
	int ret;

	ret = gnutls_rnd (GNUTLS_RND_RANDOM, dest, destlen);
	if (ret < 0) {

	}
}


static int
get_new_connection_id_cb (ngtcp2_conn *conn __attribute__((unused)),
			  ngtcp2_cid *cid, uint8_t *token,
                          size_t cidlen,
			  void *user_data __attribute__((unused)))
{
	int ret;

	ret = gnutls_rnd (GNUTLS_RND_RANDOM, cid->data, cidlen);
	if (ret < 0)
		return NGTCP2_ERR_CALLBACK_FAILURE;

	cid->datalen = cidlen;

	ret = gnutls_rnd (GNUTLS_RND_RANDOM, token, NGTCP2_STATELESS_RESET_TOKENLEN);
	if (ret < 0)
		return NGTCP2_ERR_CALLBACK_FAILURE;

	return 0;
}

static int
recv_stream_data_cb (ngtcp2_conn *conn __attribute__((unused)),
		     uint32_t flags __attribute__((unused)),
		     int64_t stream_id __attribute__((unused)),
                     uint64_t offset __attribute__((unused)),
		     const uint8_t *data, size_t datalen,
                     void *user_data,
		     void *stream_user_data __attribute__((unused)))
{
	wget_debug_printf("receiving %zu bytes from stream #%zd\n", datalen, stream_id);
	wget_quic *connection = user_data;
	wget_quic_stream *stream = wget_quic_stream_find (connection, stream_id);

	if (stream)
		wget_quic_stream_push(stream, (const char *)data, datalen, RESPONSE_DATA_BYTE);

	return 0;
}

static int
acked_stream_data_offset_cb (ngtcp2_conn *conn __attribute__((unused)),
			     int64_t stream_id,
                             uint64_t offset, uint64_t datalen,
                             void *user_data,
			     void *stream_user_data __attribute__((unused)))
{
	wget_quic *connection = user_data;
	wget_quic_stream *stream = wget_quic_stream_find (connection, stream_id);
	if (stream) {
		quic_stream_mark_acked (stream, offset + datalen);
		wget_debug_printf("acked %zu bytes on stream #%zd\n", datalen, stream_id);
	} else 
		wget_debug_printf("acked %zu bytes on no stream\n", datalen);

	return 0;
}

static int
stream_open_cb (ngtcp2_conn *conn __attribute__((unused)),
		int64_t stream_id, void *user_data)
{
  wget_quic *connection = user_data;
  wget_quic_stream *stream = wget_quic_stream_set_stream (connection, stream_id);
  if (stream)
	return 0;
  return -1;
}

static int
stream_close_cb(ngtcp2_conn *conn, uint32_t flags __attribute__((unused)),
					int64_t stream_id, uint64_t app_error_code,
					void *user_data __attribute__((unused)), 
					void *stream_user_data __attribute__((unused)))
{
	// wget_quic *connection = user_data;
	// wget_quic_stream_unset(user_data, stream_id);
	int ret = ngtcp2_conn_shutdown_stream(conn, 0, stream_id, app_error_code);
	return ret;
}

static const 
ngtcp2_callbacks callbacks = 
{
    /* Use the default implementation from ngtcp2_crypto */
    .client_initial = ngtcp2_crypto_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,

	/*These callback functions implemented in same file above*/
    .acked_stream_data_offset = acked_stream_data_offset_cb,
    .recv_stream_data = recv_stream_data_cb,
	.stream_open = stream_open_cb,
	.stream_close = stream_close_cb,
	/*These both functions are present in the ssl_gnutls.c*/
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb
};

int
get_random_cid (ngtcp2_cid *cid)
{
	uint8_t buf[NGTCP2_MAX_CIDLEN];
	int ret;

	ret = gnutls_rnd (GNUTLS_RND_RANDOM, buf, sizeof(buf));
	if (ret < 0) {
		return -1;
	}
	ngtcp2_cid_init (cid, buf, sizeof(buf));
	return 0;
}

static int 
handshake_write(wget_quic *quic)
{
	int ret;
	uint8_t buf[BUF_SIZE];
	ngtcp2_ssize n_read, n_written;
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info pi;
	ngtcp2_vec datav;
	ngtcp2_conn *conn = (ngtcp2_conn *)quic->conn;
	int64_t stream_id = -1;
	uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
	uint64_t ts = timestamp();

	ngtcp2_path_storage_zero(&ps);

	datav.base = NULL;
	datav.len = 0;

	n_written = ngtcp2_conn_writev_stream(conn, &ps.path, &pi,
					      buf, sizeof(buf),
					      &n_read,
					      flags,
					      stream_id,
					      &datav, 1,
					      ts);
	if (n_written < 0) {
		wget_error_printf("ERROR: ngtcp2_conn_writev_stream: %s\n",
			ngtcp2_strerror((int) n_written));
		return WGET_E_INVALID;
	}

	if (n_written == 0)
		return WGET_E_SUCCESS;

	ret = send_packet(quic->sockfd, buf, n_written,
			  NULL, 0);
	if (ret < 0) {
		wget_error_printf("ERROR: send_packet: %s\n", strerror(errno));
		return WGET_E_INVALID;
	}

	return WGET_E_SUCCESS;
}

#ifdef WITH_LIBNGTCP2
int 
wget_quic_ack(wget_quic *quic)
{
	if (!handshake_completed(quic))
		return WGET_E_HANDSHAKE;

	int ret;
	uint8_t buf[BUF_SIZE];
	ngtcp2_ssize n_read, n_written;
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info pi;
	ngtcp2_vec datav;
	ngtcp2_conn *conn = (ngtcp2_conn *)quic->conn;
	int64_t stream_id = -1;
	uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
	uint64_t ts = timestamp();

	ngtcp2_path_storage_zero(&ps);

	datav.base = NULL;
	datav.len = 0;

	n_written = ngtcp2_conn_writev_stream(conn, &ps.path, &pi,
					      buf, sizeof(buf),
					      &n_read,
					      flags,
					      stream_id,
					      &datav, 1,
					      ts);
	if (n_written < 0) {
		error_printf("ERROR: ngtcp2_conn_writev_stream : %s\n",
			ngtcp2_strerror((int) n_written));
		return WGET_E_INVALID;
	}

	if (n_written == 0)
		return WGET_E_SUCCESS;

	ret = send_packet(quic->sockfd, buf, n_written,
			  NULL, 0);
	if (ret < 0) {
		error_printf("ERROR: send_packet: %s\n", strerror(errno));
		return WGET_E_INVALID;
	}

	return WGET_E_SUCCESS;
}
#else
int 
wget_quic_ack(wget_quic *quic)
{
	return WGET_E_UNSUPPORTED;
}
#endif

static int 
handshake_read(wget_quic *quic)
{
	uint8_t buf[BUF_SIZE];
	ngtcp2_ssize ret;
	ngtcp2_path path;
	ngtcp2_pkt_info pi;
	struct sockaddr_storage remote_addr;
	size_t remote_addrlen = sizeof(remote_addr);
	int socket_fd = quic->sockfd;
	ngtcp2_conn *conn = (ngtcp2_conn *)quic->conn;

	for (;;) {
		remote_addrlen = sizeof(remote_addr);

		ret = recv_packet(socket_fd, buf, sizeof(buf),
				  (struct sockaddr *) &remote_addr, &remote_addrlen);
		if (ret < 0) {
			if (errno == EAGAIN)
				break;
			error_printf("ERROR: recv_packet: %s\n", strerror(errno));
			return WGET_E_UNKNOWN;
		}

		memcpy(&path, ngtcp2_conn_get_path(conn), sizeof(path));
		path.remote.addrlen = remote_addrlen;
		path.remote.addr = (struct sockaddr *) &remote_addr;

		ret = ngtcp2_conn_read_pkt(conn,
					   &path, &pi, buf, ret, timestamp());
		if (ret < 0) {
			error_printf("ERROR: ngtcp2_conn_read_pkt: %s\n",
				ngtcp2_strerror(ret));
			return WGET_E_UNKNOWN;
		}
	}

	return WGET_E_SUCCESS;
}

int 
quic_handshake(wget_quic* quic){
	int ret,
	timer_fd = quic->timerfd;
	ngtcp2_conn *conn = (ngtcp2_conn *)quic->conn;
	ngtcp2_tstamp expiry, now;
	struct itimerspec it;

	while (!ngtcp2_conn_get_handshake_completed(conn)) {
		if ((ret = handshake_write(quic)) < 0){
			return ret;
		}
		memset(&it, 0 , sizeof(it));

		expiry = ngtcp2_conn_get_expiry(conn);
		now = timestamp();
		ret = timerfd_settime(timer_fd, 0, &it, NULL);
		if (ret < 0) {
			wget_error_printf("ERROR: timerfd_settime: %s", strerror(errno));
			return WGET_E_TIMEOUT;
		}
		if (expiry < now) {
			it.it_value.tv_sec = 0;
			it.it_value.tv_nsec = 1;
		} else {
			it.it_value.tv_sec = (expiry - now) / NGTCP2_SECONDS;
			it.it_value.tv_nsec = ((expiry - now) % NGTCP2_SECONDS) / NGTCP2_NANOSECONDS;
		}

		ret = timerfd_settime(timer_fd, 0, &it, NULL);
		if (ret < 0) {
			wget_error_printf("ERROR: timerfd_settime: %s", strerror(errno));
			return WGET_E_TIMEOUT;
		}
		handshake_read(quic);
	}
	return 0;
}

static void _set_async(int fd)
{
#if ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
	unsigned long blocking = 0;

	if (ioctl(fd, FIONBIO, &blocking))
		wget_error_printf_exit("Failed to set socket to non-blocking\n");
#else
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) < 0)
		wget_error_printf_exit("Failed to get socket flags\n");

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		wget_error_printf_exit("Failed to set socket to non-blocking\n");
#endif
}

/**
 * \param[in] quic A `wget_quic` structure representing a QUIC.
 * \param[in] host Hostname or IP to connect to.
 * \param[in] port Port Number.
 * 
 * Dubug is not used as of now as used in the wget_tcp_connect
*/

#ifdef WITH_LIBNGTCP2
int 
wget_quic_connect(wget_quic *quic, const char *host, uint16_t port)
{
	struct addrinfo *ai_rp;
	int ret = WGET_E_UNKNOWN ,rc;

	if (unlikely(!quic))
		return WGET_E_INVALID;

	quic->remote_port = port;

	wget_dns_freeaddrinfo(quic->dns, &quic->addrinfo);
	xfree(quic->host);

	quic->addrinfo = wget_dns_resolve(quic->dns, host, port, quic->family, quic->preferred_family, WGET_QUIC_PROTOCOL);
	if (!quic->addrinfo)
		return WGET_E_INVALID;

	int sockfd;
	for (ai_rp = quic->addrinfo ; ai_rp != NULL ; ai_rp = ai_rp->ai_next) {
		if ((sockfd = socket(ai_rp->ai_family, ai_rp->ai_socktype | SOCK_NONBLOCK, 
				ai_rp->ai_protocol)) != -1) {
			_set_async(sockfd);
			rc = connect(sockfd, ai_rp->ai_addr, ai_rp->ai_addrlen);
			if (rc < 0 && errno != EAGAIN && errno != EINPROGRESS) {
				print_error_host(_("Failed to connect"), host);
				ret = WGET_E_CONNECT;
				close(sockfd);
			} else {
				quic->sockfd = sockfd;
				ret = wget_ssl_open_quic(quic);
				if (ret < 0) {
					/*
						Write a function similar to 
						wget_tcp_close which basically
						deinitialises the function.
					*/
					break;
				}
				if (!quic->local || !quic->remote || !quic->local->addr || !quic->remote->addr) {
					return WGET_E_MEMORY;
				}
				socklen_t len;
				quic->local->size = sizeof(quic->local->addr);
				len = (socklen_t) quic->local->size;
				getsockname(sockfd, quic->local->addr, &len);
				quic->local->size = len;	

				quic->remote->addr = ai_rp->ai_addr;
				quic->remote->size = ai_rp->ai_addrlen;
				ret = WGET_E_SUCCESS;
				break;
			}
		} else {
			print_error_host(_("Failed to create socket"), host);
			ret = WGET_E_UNKNOWN;
		}
	}
	return ret;
}
#else
int 
wget_quic_connect(wget_quic *quic, const char *host, uint16_t port)
{
	return WGET_E_UNSUPPORTED;
}
#endif

#ifdef WITH_LIBNGTCP2
int 
wget_quic_handshake(wget_quic *quic)
{
	int ret = WGET_E_INVALID;
	if (unlikely(!quic))
		return WGET_E_INVALID;

	int sockfd = quic->sockfd;			

	ngtcp2_path path =
	{
		.local = {
			.addrlen = quic->local->size,
			.addr = quic->local->addr,
		},
		.remote = {
			.addrlen = quic->remote->size,
			.addr = quic->remote->addr,
		}
	};

	ngtcp2_settings settings;
	ngtcp2_settings_default (&settings);
	settings.initial_ts = timestamp ();
	/*
		Not sure what to do with this log_printf function.
	*/
	// settings.log_printf = log_printf;
	settings.log_printf = NULL;

	ngtcp2_transport_params params;
	ngtcp2_transport_params_default (&params);
	params.initial_max_streams_uni = 3;
	params.initial_max_stream_data_bidi_local = 128 * 1024;
	params.initial_max_data = 1024 * 1024;

	ngtcp2_cid scid, dcid;
	if (get_random_cid (&scid) < 0 || get_random_cid (&dcid) < 0)
		wget_error_printf_exit("get_random_cid failed\n");

	ngtcp2_conn *conn = NULL;
	ret = ngtcp2_conn_client_new (&conn, &dcid, &scid, &path,
				NGTCP2_PROTO_VER_V1,
				&callbacks, &settings, &params, NULL,
				quic);
	if (ret < 0) {
		print_error_host(_("Failed to create a QUIC client"), quic->ssl_hostname);
		ret = WGET_E_CONNECT;
		close(sockfd);
	}
	
	quic->conn = conn;	
	ngtcp2_conn_set_tls_native_handle (quic->conn, quic->ssl_session);
	gnutls_session_set_ptr(quic->ssl_session, (void *)conn);
	int timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (timerfd < 0) {
		print_error_host(_("Timerfd Failed"),quic->ssl_hostname);
		ret = WGET_E_UNKNOWN;
		close(sockfd);
	}

	quic->timerfd = timerfd;	
	if ((ret = quic_handshake(quic)) < 0) {
		return ret;
	}

	ret = wget_quic_ack(quic);
	return WGET_E_SUCCESS;
}
#else
int 
wget_quic_handshake(wget_quic *quic)
{
	return WGET_E_UNSUPPORTED;
}
#endif

/* Stream Struct Getter and Setter functions present [As Required] */

void 
quic_stream_mark_sent(wget_quic_stream *stream, ngtcp2_ssize offset)
{
	stream->sent_offset += offset;
}

wget_byte *
quic_stream_peek_data(wget_quic_stream *stream)
{
	if (!stream)
		return NULL;

	wget_byte *byte = wget_queue_peek_untransmitted_node(stream->buffer);
	return byte;
}

void
quic_stream_mark_acked (wget_quic_stream *stream, size_t offset)
{
  	while (stream && stream->ack_offset < offset) {
		wget_byte *head  = (wget_byte *)wget_queue_peek_transmitted_node(stream->buffer);

		if (stream->ack_offset + wget_byte_get_size (head) > offset)
			break;

		stream->ack_offset += wget_byte_get_size (head);
		wget_queue_dequeue_transmitted_node(stream->buffer);
    }
}

ssize_t send_packet(int fd, const uint8_t *data, size_t data_size,
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

static int handshake_completed(wget_quic *quic)
{
	return (quic && quic->conn && ngtcp2_conn_get_handshake_completed(
		(ngtcp2_conn *)quic->conn));
}

ssize_t recv_packet(int fd, uint8_t *data, size_t data_size,
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
		ret = recvmsg(fd, &msg, MSG_DONTWAIT);
	while (ret < 0 && errno == EINTR);

	*remote_addrlen = msg.msg_namelen;

	return ret;
}

/*
	As of now not decided on the flags.
	To have NGTCP2_WRITE_STREAM_FLAG_MORE will be decided as per
	the options from the user maybe. Not clear on that as of now.
	Subject to question.
	Also signatures of these functions have to be discussed.
*/

static int 
write_stream(wget_quic *quic, wget_quic_stream *stream)
{
	int ret;
	bool sent = false;
	uint8_t buf[BUF_SIZE];

	ngtcp2_path_storage ps;
	ngtcp2_path_storage_zero(&ps);

	ngtcp2_pkt_info pi;
	memset(&pi, 0, sizeof(pi));
	uint64_t ts = timestamp();

	// uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
	uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;

	ngtcp2_ssize n_read, n_written = 0;

	ngtcp2_vec datav;
	int64_t stream_id;
	wget_byte *byte;

	while(1){
		byte = quic_stream_peek_data(stream);
		if (!byte)
			break;
		datav.base = wget_byte_get_data(byte);
		datav.len = wget_byte_get_size(byte);
		stream_id = wget_quic_stream_get_id(stream);

		n_written = ngtcp2_conn_writev_stream(quic->conn, &ps.path, &pi,
							buf, sizeof(buf),
							&n_read,
							flags,
							stream_id,
							&datav, 1,
							ts);
		if (n_written < 0) {
			wget_error_printf("ERROR: ngtcp2_conn_writev_stream: %s\n",
				ngtcp2_strerror((int) n_written));
			return n_written;
		}

		wget_byte_set_transmitted(byte);
		sent = true;

		if (n_written == 0)
			return 0;

		if (n_read > 0)
			quic_stream_mark_sent(stream, n_read);
	}

	if (sent){
		ret = send_packet(quic->sockfd, buf, n_written,
				quic->remote->addr,
				quic->remote->size);
		if (ret < 0) {
			wget_error_printf("ERROR: send_packet: %s\n", strerror(errno));
			return -1;
		}
		sent = false;
	}

	return n_written;
}

/*
	As of now the function signature kept is such that,
	the user has to initially push the data into a stream.
	using functions related to stream and then call this
	function to write the data in the stream using the 
	active QUIC connection.
	As the logic of which stream to be selected from the 
	available MAX_STREAMS is discussed, this function will
	be updated.
*/

#ifdef WITH_LIBNGTCP2
ssize_t
wget_quic_write(wget_quic *quic, wget_quic_stream *stream)
{

	ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry (quic->conn);
	ngtcp2_tstamp now = timestamp ();
	struct itimerspec it;
	int ret, n_write;

	if (!handshake_completed(quic)) {
		return WGET_E_HANDSHAKE;
	}
	
	ret = wget_ready_2_transfer(quic->sockfd, quic->timerfd, WGET_IO_WRITABLE);
	if (ret < 0) {
		return WGET_E_TIMEOUT;
	}

	do {
		n_write = write_stream(quic, stream);
		if (n_write != NGTCP2_ERR_WRITE_MORE && n_write < 0){
			return WGET_E_UNKNOWN;
		}
	} while (n_write == NGTCP2_ERR_WRITE_MORE);

	memset (&it, 0, sizeof (it));

	ret = timerfd_settime(quic->timerfd, 0, &it, NULL);
	if (ret < 0) {
		wget_error_printf("ERROR: timerfd_settime: %s", strerror(errno));
		return -1;
	}
	if (expiry < now) {
		it.it_value.tv_sec = 0;
		it.it_value.tv_nsec = 1;
	} else {
		it.it_value.tv_sec = (expiry - now) / NGTCP2_SECONDS;
		it.it_value.tv_nsec = ((expiry - now) % NGTCP2_SECONDS) / NGTCP2_NANOSECONDS;
	}

	ret = timerfd_settime(quic->timerfd, 0, &it, NULL);
	if (ret < 0) {
		wget_error_printf("ERROR: timerfd_settime: %s", strerror(errno));
		return -1;
	}

	return n_write;

}
#else
ssize_t
wget_quic_write(wget_quic *quic, wget_quic_stream *stream)
{
	return WGET_E_UNSUPPORTED;
}
#endif

/*
	Very basic implementation of the wget_quic_read.
	Will upadte the implemenatation after the current 
	implementation is tested.
*/

static int
read_stream(wget_quic *quic)
{
	ngtcp2_ssize ret;
	uint8_t buf[BUF_SIZE];
	struct sockaddr_storage remote_addr;
	size_t remote_addrlen = sizeof(remote_addr);
	ngtcp2_path path;
	ngtcp2_pkt_info pi;
	uint64_t ts = timestamp();

	while(1) {
		remote_addrlen = sizeof(remote_addr);

		ret = recv_packet(quic->sockfd,
				  (uint8_t *)buf, sizeof(buf),
				  (struct sockaddr *) &remote_addr, &remote_addrlen);
		if (ret < 0) {
			if (errno == EAGAIN)
				break;
			wget_error_printf("ERROR: recv_packet: %s\n", strerror(errno));
			return -1;
		}

		memcpy(&path, ngtcp2_conn_get_path(quic->conn), sizeof(path));
		path.remote.addrlen = remote_addrlen;
		path.remote.addr = (struct sockaddr *) &remote_addr;

		memset(&pi, 0, sizeof(pi));

		ret = ngtcp2_conn_read_pkt(quic->conn, &path, &pi, (const uint8_t *)buf, ret, ts);
		if (ret < 0) {
			wget_error_printf("ERROR: ngtcp2_conn_read_pkt: %s\n",
				ngtcp2_strerror(ret));
			return -1;
		}
	}
	return WGET_E_SUCCESS;
}

#ifdef WITH_LIBNGTCP2
int 
wget_quic_read(wget_quic *quic)
{
	if (!handshake_completed(quic)) {
		return WGET_E_HANDSHAKE;
	}

	int ret = wget_ready_2_transfer(quic->sockfd, quic->timerfd, WGET_IO_READABLE);
	if (ret < 0) {
		return WGET_E_TIMEOUT;
	}

	ret = read_stream(quic);
	if (ret < 0) {
		return WGET_E_UNKNOWN;
	}

	ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry (quic->conn);
	ngtcp2_tstamp now = timestamp ();
	struct itimerspec it;

	memset (&it, 0, sizeof (it));

	ret = timerfd_settime (quic->timerfd, 0, &it, NULL);
	if (ret < 0) {
		wget_error_printf("ERROR: timerfd_settime: %s", strerror(errno));
		return -1;
	}
	if (expiry < now) {
		it.it_value.tv_sec = 0;
		it.it_value.tv_nsec = 1;
	} else {
		it.it_value.tv_sec = (expiry - now) / NGTCP2_SECONDS;
		it.it_value.tv_nsec = ((expiry - now) % NGTCP2_SECONDS) / NGTCP2_NANOSECONDS;
	}

	ret = timerfd_settime (quic->timerfd, 0, &it, NULL);
	if (ret < 0) {
		wget_error_printf("ERROR: timerfd_settime: %s", strerror(errno));
		return -1;
	}

	return ret;
}
#else
int 
wget_quic_read(wget_quic *quic)
{
	return WGET_E_UNSUPPORTED;
}
#endif

#ifdef WITH_LIBNGTCP2
int
wget_quic_rw_once(wget_quic *quic, wget_quic_stream *stream)
{
	int ret = -1;
	ret = wget_quic_write(quic, stream);
	if (ret < 0)
		return ret;

	ret = wget_quic_read(quic);
	if (ret < 0)
		return ret;

	wget_byte *byte = (wget_byte *)wget_queue_dequeue_data_node(wget_quic_stream_get_buffer(stream));
	if (byte){
		wget_debug_printf("Data recorded : %s\n", (char *)wget_byte_get_data(byte));
		wget_debug_printf("Data recorded Type : %d\n", wget_byte_get_type(byte));
	}

	ret = wget_quic_ack(quic);
		
	return ret;
}
#else
int
wget_quic_rw_once(wget_quic *quic, wget_quic_stream *stream)
{
	return WGET_E_UNSUPPORTED;
}
#endif