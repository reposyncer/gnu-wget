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
#include <ngtcp2/ngtcp2.h>

#if ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
# include <sys/ioctl.h>
#else
# include <fcntl.h>
#endif

#include <wget.h>
#include "private.h"
#include "net.h"


#define BUF_SIZE 1280

/* wget_quic getter and setter functions */

void
wget_quic_add_stream (wget_quic *quic, wget_quic_stream *stream)
{
  wget_list_append (quic->streams, stream, sizeof(stream));
}

wget_quic_stream *
wget_quic_find_stream (wget_quic *quic, int64_t stream_id)
{
  for (void *l = (void *)wget_quic_get_streams(quic) + 1; l; l = wget_list_getnext(l))
    {
      wget_quic_stream *stream = (wget_quic_stream *)l;
	  //Stream_get_id is not very good name. Write getter and setter functions for Stream as well.
      if (stream_get_id (stream) == stream_id)
        return stream;
    }
  return NULL;
}

ngtcp2_conn *
wget_quic_get_ngtcp2_conn (wget_quic *quic)
{
  return quic->conn;
}

wget_list* 
wget_quic_get_streams(wget_quic *quic)
{
	return quic->streams;
}

void
wget_quic_set_ngtcp2_conn (wget_quic *quic, ngtcp2_conn *conn)
{
  quic->conn = conn;
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

struct sockaddr *wget_quic_get_local_addr (wget_quic *quic, size_t *local_addrlen)
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

/* wget_quic_stream getter and setter and utlitly functions [Only Required Implemented as of Now] */
int64_t 
wget_quic_stream_get_id(wget_quic_stream *stream)
{
	return stream->id;
}

void
wget_quic_stream_mark_acked (wget_quic_stream *stream, size_t offset)
{
  while (!wget_queue_is_empty (stream->buffer))
    {
      stream_byte *head  = wget_queue_peek (stream->buffer);
      if (stream->ack_offset + stream_byte_get_size (head) > offset)
        break;

      stream->ack_offset += stream_byte_get_size (head);
      head = stream_queue_dequeue (stream->buffer);
    }
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
//Apperently as per my observation, there is a ref count in the stream_byte.
//This should handle duplicate data. Not yet handled in the implementation.
typedef struct stream_byte
{
	unsigned char* data;
	size_t size;
}stream_byte;

stream_byte *
stream_byte_new(const unsigned char *data, size_t size)
{
	stream_byte *bytes = wget_malloc(sizeof(stream_byte));
	if (bytes){
		bytes->data = wget_malloc(size);
		if (!bytes->data){
			xfree(bytes->data);
			return NULL;
		}
		memcpy((void *)bytes->data, data, size);
		bytes->size = size;
	}
	return bytes;
}

size_t 
stream_byte_get_size(const stream_byte *bytes)
{
	return bytes->size;
}

const unsigned char *
stream_byte_get_data(const stream_byte* bytes)
{
	return bytes->data;
}

void 
stream_byte_free(stream_byte *bytes)
{
	xfree(bytes->data);
	xfree(bytes);
}

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
  wget_quic_stream *stream = wget_quic_find_stream (connection, stream_id);
  if (stream)
    wget_quic_stream_mark_acked (stream, offset + datalen);
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
	ngtcp2_conn *conn = wget_quic_get_ngtcp2_conn(quic);
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
	ngtcp2_conn *conn = wget_quic_get_ngtcp2_conn(quic);

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
	ngtcp2_conn *conn = wget_quic_get_ngtcp2_conn(cli->quic);
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
				settings.log_printf = log_printf;

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
				
				wget_quic_set_ngtcp2_conn(quic, conn);					
				wget_quic_set_remote_addr(quic, ai_rp->ai_addr, ai_rp->ai_addrlen);
				wget_ssl_quic_setup(quic->ssl_session, quic->conn);
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

/*
QUIC protocol integration with wget2 library.
Initial Implemenations :

wget_quic_connect
wget_quic_read
wget_quic_write

*/