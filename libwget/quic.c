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
#include <ngtcp2/ngtcp2.h>
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

void *
wget_quic_get_ngtcp2_conn (wget_quic *quic)
{
  return (void *)quic->conn;
}

wget_list* 
wget_quic_get_streams(wget_quic *quic)
{
	return quic->streams;
}

void
wget_quic_set_ngtcp2_conn (wget_quic *quic, void *conn)
{
  quic->conn = (ngtcp2_conn *)conn;
}

int
wget_quic_get_socket_fd (wget_quic *quic)
{
  return quic->sockfd;
}

void
wget_quic_set_socket_fd (wget_quic *quic, int socketfd)
{
  quic->sockfd = socketfd;
}

int
wget_quic_get_timer_fd (wget_quic *quic)
{
  return quic->timerfd;
}

struct sockaddr *
wget_quic_get_local_addr (wget_quic *quic, size_t *local_addrlen)
{
  *local_addrlen = quic->local->size;
  return quic->local->addr;
}

void
wget_quic_set_local_addr (wget_quic *quic,
                           struct sockaddr *local_addr,
                           size_t local_addrlen)
{
  memcpy (quic->local->addr, local_addr, local_addrlen);
  quic->local->size = local_addrlen;
}

void
wget_quic_set_remote_addr (wget_quic *quic,
                           struct sockaddr *remote_addr,
                           size_t remote_addrlen)
{
  memcpy (quic->remote->addr, remote_addr, remote_addrlen);
  quic->remote->size = remote_addrlen;
}

void *
wget_quic_get_ssl_session(wget_quic *quic)
{
	return quic->ssl_session;
}

void
wget_quic_set_ssl_session(wget_quic *quic, void *session)
{	
	quic->ssl_session = session;
}

/*

Structs present : 

Struct similar to GBytes.
A node of this struct is pushed to the GQueue which is present in the struct Stream
This struct Stream is appended in the Glist present in the struct Connection. 

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
	if (ret < 0){

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
		     int64_t stream_id,
                     uint64_t offset __attribute__((unused)),
		     const uint8_t *data, size_t datalen,
                     void *user_data __attribute__((unused)),
		     void *stream_user_data __attribute__((unused)))
{
  write (STDOUT_FILENO, data, datalen);
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
  if (stream)
    quic_stream_mark_acked (stream, offset + datalen);
  return 0;
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
	/*These both functions are present in the ssl_gnutls.c*/
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb,
};

ssize_t 
send_packet(int fd, const uint8_t *data, size_t data_size,
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

int
get_random_cid (ngtcp2_cid *cid)
{
	uint8_t buf[NGTCP2_MAX_CIDLEN];
	int ret;

	ret = gnutls_rnd (GNUTLS_RND_RANDOM, buf, sizeof(buf));
	if (ret < 0)
	{
		return -1;
	}
	ngtcp2_cid_init (cid, buf, sizeof(buf));
	return 0;
}


ssize_t 
recv_packet(int fd, uint8_t *data, size_t data_size,
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

static int 
handshake_write(wget_quic *quic)
{
	int ret;
	uint8_t buf[BUF_SIZE];
	ngtcp2_ssize n_read, n_written;
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info pi;
	ngtcp2_vec datav;
	ngtcp2_conn *conn = (ngtcp2_conn *)wget_quic_get_ngtcp2_conn(quic);
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
		error_printf("ERROR: ngtcp2_conn_writev_stream: %s\n",
			ngtcp2_strerror((int) n_written));
		return WGET_E_INVALID;
	}

	if (n_written == 0)
		return WGET_E_SUCCESS;

	ret = send_packet(wget_quic_get_socket_fd(quic), buf, n_written,
			  NULL, 0);
	if (ret < 0) {
		error_printf("ERROR: send_packet: %s\n", strerror(errno));
		return WGET_E_INVALID;
	}

	return WGET_E_SUCCESS;
}

static int 
handshake_read(wget_quic *quic)
{
	uint8_t buf[BUF_SIZE];
	ngtcp2_ssize ret;
	ngtcp2_path path;
	ngtcp2_pkt_info pi;
	struct sockaddr_storage remote_addr;
	size_t remote_addrlen = sizeof(remote_addr);
	int socket_fd = wget_quic_get_socket_fd(quic);
	ngtcp2_conn *conn = (ngtcp2_conn *)wget_quic_get_ngtcp2_conn(quic);

	for (;;) {
		remote_addrlen = sizeof(remote_addr);

		ret = recv_packet(socket_fd, buf, sizeof(buf),
				  (struct sockaddr *) &remote_addr, &remote_addrlen);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
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
}

int 
quic_handshake(wget_quic_client* cli){
	int ret,
	timer_fd = wget_quic_get_timer_fd(cli->quic);
	ngtcp2_conn *conn = (ngtcp2_conn *)wget_quic_get_ngtcp2_conn(cli->quic);
	ngtcp2_tstamp expiry, now;
	struct itimerspec it;

	while (!ngtcp2_conn_get_handshake_completed(conn)){
		if ((ret = handshake_write(cli->quic)) < 0){
			return ret;
		}

		expiry = ngtcp2_conn_get_expiry(conn);
		now = timestamp();
		ret = timerfd_settime(timer_fd, 0, &it, NULL);
		if (ret < 0) {
			fprintf(stderr, "ERROR: timerfd_settime: %s", strerror(errno));
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
			fprintf(stderr, "ERROR: timerfd_settime: %s", strerror(errno));
			return WGET_E_TIMEOUT;
		}
		handshake_read(cli->quic);
	}
	return 0;
}

/**
 * \param[in] cli A `wget_quic_client` structure representing a QUIC client.
 * \param[in] host Hostname or IP to connect to.
 * \param[in] port Port Number.
 * 
 * Dubug is not used as of now as used in the wget_tcp_connect
*/

int 
wget_quic_connect(wget_quic_client *cli, const char *host, uint16_t port)
{
	wget_quic* quic = cli->quic;
	struct addrinfo *ai_rp;
	int ret ,rc;

	if (unlikely(!quic))
		return WGET_E_INVALID;

	wget_dns_freeaddrinfo(quic->dns, &quic->addrinfo);
	xfree(quic->host);

	quic->addrinfo = wget_dns_resolve_quic(quic->dns, host, port, quic->family, quic->preferred_family);
	
	for (ai_rp = quic->addrinfo ; ai_rp != NULL ; ai_rp = ai_rp->ai_next){
		int sockfd;
		if ((sockfd = socket(ai_rp->ai_family, ai_rp->ai_socktype | SOCK_NONBLOCK, ai_rp->ai_protocol) != -1)){
			_set_async(sockfd);
			if (quic->bind_addrinfo) {
				if(bind(sockfd, quic->bind_addrinfo->ai_addr, quic->bind_addrinfo->ai_addrlen) != 0) {
					print_error_host(_("Failed to bind"), host);
					close(sockfd);
					return WGET_E_UNKNOWN;
				}
			}
			rc = connect(sockfd, ai_rp->ai_addr, ai_rp->ai_addrlen);
			if (rc < 0 && errno != EAGAIN && errno != EINPROGRESS) {
				print_error_host(_("Failed to connect"), host);
				ret = WGET_E_CONNECT;
				close(sockfd);
			} else {
				wget_quic_set_socket_fd(quic, sockfd);
				ret = wget_ssl_open_quic(quic);
				if (ret == WGET_E_CERTIFICATE){
					/*
						Write a function similar to 
						wget_tcp_close which basically
						deinitialises the function.
					*/
					break;
				}
				getsockname(sockfd, quic->local->addr, (socklen_t *)&quic->local->size);

				ngtcp2_path path =
				{
					.local = {
						.addrlen = quic->local->size,
						.addr = quic->local->addr,
					},
					.remote = {
						.addrlen = ai_rp->ai_addrlen,
						.addr = ai_rp->ai_addr,
					}
				};

				ngtcp2_settings settings;
				ngtcp2_settings_default (&settings);
				settings.initial_ts = timestamp ();
				/*
					Not sure what to do with this log_printf function.
				*/
				settings.log_printf = wget_info_printf;

				ngtcp2_transport_params params;
				ngtcp2_transport_params_default (&params);
				params.initial_max_streams_uni = 3;
				params.initial_max_stream_data_bidi_local = 128 * 1024;
				params.initial_max_data = 1024 * 1024;

				ngtcp2_cid scid, dcid;
				if (get_random_cid (&scid) < 0 || get_random_cid (&dcid) < 0)
					error (EXIT_FAILURE, EINVAL, "get_random_cid failed\n");

				ngtcp2_conn *conn = NULL;
				ret = ngtcp2_conn_client_new (&conn, &dcid, &scid, &path,
							NGTCP2_PROTO_VER_V1,
							&callbacks, &settings, &params, NULL,
							quic);
				if (ret < 0){
					print_error_host(_("Failed to create a QUIC client"), host);
					ret = WGET_E_CONNECT;
					close(sockfd);
				}
				
				wget_quic_set_ngtcp2_conn(quic, (void *)conn);					
				wget_quic_set_remote_addr(quic, ai_rp->ai_addr, ai_rp->ai_addrlen);
				ngtcp2_conn_set_tls_native_handle (quic->conn, quic->ssl_session);
				quic->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
				if (quic->timerfd < 0){
					print_error_host(_("Timerfd Failed"), host);
					ret = WGET_E_UNKNOWN;
					close(sockfd);
				}
				if ((ret = quic_handshake(cli)) < 0){
					return ret;
				}
				return WGET_E_SUCCESS;
			}
		} else {
			print_error_host(_("Failed to create socket"), host);
			ret = WGET_E_UNKNOWN;
		}
	}
	return ret;
}

/* Stream Struct Getter and Setter functions present [As Required] */

static wget_quic_stream *_stream_new(int64_t id)
{
	wget_quic_stream *stream = wget_malloc(sizeof(wget_quic_stream));
	if (!stream)
		return NULL;
	stream->id  = id;
	stream->buffer = NULL;
	stream->ack_offset = 0;
	stream->sent_offset = 0;
	return stream;
}

wget_quic_stream *
wget_quic_stream_new(void *quic_conn)
{
	int retval;
	int64_t stream_id;
	ngtcp2_conn *conn = (ngtcp2_conn *)quic_conn;

	if(!ngtcp2_conn_get_streams_bidi_left(conn)){
		wget_error_printf("Error: Cannot open a new stream!");
		return NULL;
	}

	if((retval = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL)) < 0){
		wget_error_printf("Error: Cannot create a new bidirection stream : &d", retval);
		return NULL;
	}
	return _stream_new(stream_id);
}


int 
wget_quic_stream_push(wget_quic_stream *stream, const char *data, size_t datalen)
{
	wget_byte *buf;
	if (stream->buffer == NULL){
		stream->buffer = wget_queue_init();
		if (!stream->buffer){
			return WGET_E_MEMORY;
		}
		if ((buf = wget_byte_new(data, datalen)) == NULL){
			return WGET_E_MEMORY;
		}
		if (wget_queue_enqueue(stream->buffer, buf, sizeof(buf)) == NULL){
			return WGET_E_MEMORY;
		}
	}else{
		if ((buf = wget_byte_new(data, datalen)) == NULL){
			return WGET_E_MEMORY;
		}
		if (wget_queue_enqueue(stream->buffer, buf, sizeof(buf)) == NULL){
			return WGET_E_MEMORY;
		}
	}
	return datalen;
}

wget_quic_stream *
wget_quic_stream_find (wget_quic *quic, int64_t stream_id)
{
  for (void *l = (void *)wget_quic_get_streams(quic) + 1; l; l = wget_list_getnext(l))
    {
      wget_quic_stream *stream = (wget_quic_stream *)l;
	  //Stream_get_id is not very good name. Write getter and setter functions for Stream as well.
      if (wget_quic_stream_get_id (stream) == stream_id)
        return stream;
    }
  return NULL;
}

int64_t 
wget_quic_stream_get_id(wget_quic_stream *stream)
{
	return stream->id;
}

void 
quic_stream_mark_sent(wget_quic_stream *stream, ngtcp2_ssize offset)
{
	stream->sent_offset += offset;
}

int 
quic_stream_peek_data(wget_quic_stream *stream, ngtcp2_vec *datav)
{
	wget_byte *byte = wget_queue_peek(stream->buffer);
	if (!byte){
		return WGET_E_MEMORY;
	}
	datav->base = wget_byte_get_data(byte);
	datav->len = wget_byte_get_size(byte);
	return WGET_E_SUCCESS;
}

void
quic_stream_mark_acked (wget_quic_stream *stream, size_t offset)
{
  while (!wget_queue_is_empty (stream->buffer))
    {
      wget_byte *head  = wget_queue_peek (stream->buffer);
      if (stream->ack_offset + wget_byte_get_size (head) > offset)
        break;

      stream->ack_offset += wget_byte_get_size (head);
      head = stream_queue_dequeue (stream->buffer);
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
	return ngtcp2_conn_get_handshake_completed(
		(ngtcp2_conn *)wget_quic_get_ngtcp2_conn(quic));
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

int connection_read(wget_quic *quic)
{
	uint8_t buf[BUF_SIZE];
	ngtcp2_ssize ret;
	struct sockaddr_storage remote_addr;
	size_t remote_addrlen = sizeof(remote_addr);
	ngtcp2_path path;
	ngtcp2_pkt_info pi;

	for (;;) {
		remote_addrlen = sizeof(remote_addr);

		ret = recv_packet(wget_quic_get_socket_fd(quic),
				  buf, sizeof(buf),
				  (struct sockaddr *) &remote_addr, &remote_addrlen);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fprintf(stderr, "ERROR: recv_packet: %s\n", strerror(errno));
			return -1;
		}

		memcpy(&path, ngtcp2_conn_get_path((ngtcp2_conn *)wget_quic_get_ngtcp2_conn(quic)), sizeof(path));
		path.remote.addrlen = remote_addrlen;
		path.remote.addr = (struct sockaddr *) &remote_addr;

		memset(&pi, 0, sizeof(pi));

		ret = ngtcp2_conn_read_pkt((ngtcp2_conn *)wget_quic_get_ngtcp2_conn(quic), &path, &pi, buf, ret, timestamp());
		if (ret < 0) {
			fprintf(stderr, "ERROR: ngtcp2_conn_read_pkt: %s\n",
				ngtcp2_strerror(ret));
			return -1;
		}
	}

	return 0;
}

static int write_handshake(wget_quic *quic)
{
	int ret;
	uint8_t buf[BUF_SIZE];

	ngtcp2_path_storage ps;
	ngtcp2_path_storage_zero(&ps);

	ngtcp2_pkt_info pi;
	uint64_t ts = timestamp();

	uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

	ngtcp2_vec datav;
	int64_t stream_id;

	datav.base = NULL;
	datav.len = 0;
	stream_id = -1;

	ngtcp2_ssize n_read, n_written;

	n_written = ngtcp2_conn_writev_stream((ngtcp2_conn *)wget_quic_get_ngtcp2_conn(quic), &ps.path, &pi,
					      buf, sizeof(buf),
					      &n_read,
					      flags,
					      stream_id,
					      &datav, 1,
					      ts);
	if (n_written < 0) {
		fprintf(stderr, "ERROR: ngtcp2_conn_writev_stream: %s\n",
			ngtcp2_strerror((int) n_written));
		return -1;
	}

	if (n_written == 0)
		return 0;

	ret = send_packet(wget_quic_get_socket_fd(quic), buf, n_written,
			  quic->remote->addr,
			  quic->remote->size);
	if (ret < 0) {
		fprintf(stderr, "ERROR: send_packet: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int connection_write(wget_quic *quic)
{
	int ret = write_handshake(quic);

	if (ret < 0)
		return -1;

	ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry ((ngtcp2_conn *)wget_quic_get_ngtcp2_conn(quic));
	ngtcp2_tstamp now = timestamp ();
	struct itimerspec it;

	memset (&it, 0, sizeof (it));

	ret = timerfd_settime (wget_quic_get_timer_fd(quic), 0, &it, NULL);
	if (ret < 0) {
		fprintf(stderr, "ERROR: timerfd_settime: %s", strerror(errno));
		return -1;
	}
	if (expiry < now) {
		it.it_value.tv_sec = 0;
		it.it_value.tv_nsec = 1;
	} else {
		it.it_value.tv_sec = (expiry - now) / NGTCP2_SECONDS;
		it.it_value.tv_nsec = ((expiry - now) % NGTCP2_SECONDS) / NGTCP2_NANOSECONDS;
	}

	ret = timerfd_settime (wget_quic_get_timer_fd(quic), 0, &it, NULL);
	if (ret < 0) {
		fprintf(stderr, "ERROR: timerfd_settime: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int handle_socket(wget_quic *quic, const struct epoll_event *event)
{
	int ret;

	if (event->events & EPOLLIN) {
		if ((ret = connection_read(quic)) < 0)
			return -1;
	}

	if (event->events & EPOLLOUT) {
		if ((ret = connection_write(quic)) < 0)
			return -1;
	}

	return 0;
}

static int handle_timer(wget_quic *quic, const struct epoll_event *event)
{
	int ret;
	ngtcp2_conn *conn = (ngtcp2_conn *)wget_quic_get_ngtcp2_conn(quic);

	if ((ret = ngtcp2_conn_handle_expiry(conn, timestamp())) < 0) {
		wget_error_printf("ERROR: ngtcp2_conn_handle_expiry: %s\n",
			ngtcp2_strerror(ret));
		return -1;
	}

	if ((ret = connection_write(quic)) < 0)
		return -1;

	return 0;
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
	uint8_t buf[BUF_SIZE];

	ngtcp2_path_storage ps;
	ngtcp2_path_storage_zero(&ps);

	ngtcp2_pkt_info pi;
	uint64_t ts = timestamp();

	/* uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE; */
	uint32_t flags = 0;

	ngtcp2_vec datav;
	int64_t stream_id;

	stream_id = wget_quic_stream_get_id(stream);
	/* datav.len = stream_peek_data(stream, (uint8_t **) &datav.base); */
	quic_stream_peek_data(stream, &datav);

	ngtcp2_ssize n_read, n_written;

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
		return -1;
	}

	if (n_written == 0)
		return 0;

	if (n_read > 0)
		quic_stream_mark_sent(stream, n_read);

	ret = send_packet(quic->sockfd, buf, n_written,
			  quic->remote->addr,
			  quic->remote->size);
	if (ret < 0) {
		wget_error_printf("ERROR: send_packet: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}


ssize_t
wget_quic_write(wget_quic_client *cli, wget_quic_stream *stream)
{
	int ret = write_stream(cli->quic, stream);
	if (ret < 0){
		return WGET_E_UNKNOWN;
	}

	ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry (cli->quic->conn);
	ngtcp2_tstamp now = timestamp ();
	struct itimerspec it;

	memset (&it, 0, sizeof (it));

	ret = timerfd_settime (cli->quic->timerfd, 0, &it, NULL);
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

	ret = timerfd_settime (cli->quic->timerfd, 0, &it, NULL);
	if (ret < 0) {
		wget_error_printf("ERROR: timerfd_settime: %s", strerror(errno));
		return -1;
	}
	
	int epoll_fd, nfds;
	struct epoll_event ev, events[MAX_EVENTS];

	if ((epoll_fd = epoll_create(4)) < 0) {
		wget_error_printf("ERROR: epoll_create\n");
		return -1;
	}

	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = wget_quic_get_socket_fd(cli->quic);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) < 0) {
		wget_error_printf("ERROR: epoll_ctl\n");
		return -1;
	}

	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = wget_quic_get_timer_fd(cli->quic);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) < 0) {
		wget_error_printf("ERROR: epoll_ctl\n");
		return -1;
	}

	while (!handshake_completed(cli->quic)) {
		nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
		if (nfds < 0) {
			wget_error_printf("ERROR: epoll_wait\n");
			return -1;
		}

		for (unsigned i = 0; i < nfds; i++) {
			if (events[i].data.fd == wget_quic_get_socket_fd(cli->quic)) {
				if (handle_socket(cli->quic, &events[i]) < 0)
					return -1;
			}
			if (events[i].data.fd == wget_quic_get_timer_fd(cli->quic)) {
				if (handle_timer(cli->quic, &events[i]) < 0)
					return -1;
			}
		}
	}

	close(epoll_fd);

	return 0;

}