#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <c-ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#ifdef WITH_LIBNGHTTP3
#include <nghttp3/nghttp3.h>

#endif

#ifdef WITH_LIBNGTCP2
#include <ngtcp2/ngtcp2.h>

#endif

#if ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
# include <sys/ioctl.h>
#else
# include <fcntl.h>
#endif

#include <wget.h>
#include "private.h"
#include "net.h"
#include "http.h"

static int _stop_sending(ngtcp2_conn *conn,
			 int64_t stream_id, uint64_t app_error_code);
static int _reset_stream(ngtcp2_conn *conn,
			 int64_t stream_id, uint64_t app_error_code);
static int _http3_consume(ngtcp2_conn *conn, uint64_t 
			 stream_id, size_t nconsumed);
static int _http3_write_data(wget_quic* quic, int64_t stream_id, const uint8_t *data, 
				 				size_t datalen, uint8_t type);
static void init_nv(nghttp3_nv *nv, const char *name, const char *value);
static int _call_data_sender(int64_t stream_id, const nghttp3_vec *vec, size_t veccnt,
			     int (*_cb_func)(int64_t, const void*, void *), void *userdata);
void http3_stream_mark_acked (wget_quic_stream *stream, size_t offset);
int http3_stream_push(int64_t stream_id, const void* vector,  void *userdata);

/* Name of the struct does not make a lot of sense as of now.
   It will be changed
*/
struct http3_stream_context {
	wget_http_response
		*resp;
};

struct http3_stream_context *http3_ctx = NULL;

void http3_stream_mark_acked(wget_quic_stream *stream, size_t datalen)
{
  	while (stream) {
		wget_byte *head = (wget_byte *)wget_queue_peek_transmitted_node(stream->buffer);
		if (wget_byte_get_size(head) > datalen)
			break;

		stream->ack_offset += wget_byte_get_size(head);
		datalen -= wget_byte_get_size(head);
		wget_queue_dequeue_transmitted_node(stream->buffer);
		return;
	}
}

/* Close read side of a stream abruptly */
static int _stop_sending(ngtcp2_conn *conn,
			 int64_t stream_id, uint64_t app_error_code)
{
	int ret = ngtcp2_conn_shutdown_stream_read(conn, 0,
						   stream_id, app_error_code);
	if (ret < 0) {
		error_printf("ERROR: ngtcp2_conn_shutdown_stream_read: %s\n",
			     ngtcp2_strerror(ret));
		return -1;
	}

	return 0;
}

/* Close write side of a stream abruptly */
static int _reset_stream(ngtcp2_conn *conn,
			 int64_t stream_id, uint64_t app_error_code)
{
	int ret = ngtcp2_conn_shutdown_stream_write(conn, 0,
						    stream_id, app_error_code);
	if (ret < 0) {
		error_printf("ERROR: ngtcp2_conn_shutdown_stream_write: %s\n",
			     ngtcp2_strerror(ret));
		return -1;
	}

	return 0;
}

static int _http3_consume(ngtcp2_conn *conn, uint64_t stream_id, size_t nconsumed)
{
	int ret = ngtcp2_conn_extend_max_stream_offset(conn, stream_id, nconsumed);
	if (ret < 0)
		return ret;
	ngtcp2_conn_extend_max_offset(conn, nconsumed);
	return 0;
}

static int _http3_write_data(wget_quic* quic, int64_t stream_id, const uint8_t *data, 
			     size_t datalen, uint8_t type)
{
	if (!quic)
		return -1;

	wget_quic_stream *stream = wget_quic_stream_find(quic, stream_id);
	if(stream) {
		int ret = wget_quic_stream_push(stream, (const char *)data, datalen, type);
		if (ret < 0)
			return ret;
		return 0;
	}
	return -1;
}

static int recv_header_cb(nghttp3_conn *h3conn __attribute__((unused)), 
			  int64_t stream_id __attribute__((unused)),
			  int32_t token __attribute__((unused)),
			  nghttp3_rcbuf *name, nghttp3_rcbuf *value, 
			  uint8_t flags __attribute__((unused)),
			  void *conn_user_data __attribute__((unused)), 
			  void *stream_user_data __attribute__((unused)))
{
	nghttp3_vec namevec, valuevec;
	namevec = nghttp3_rcbuf_get_buf(name);
	valuevec = nghttp3_rcbuf_get_buf(value);

	debug_printf("Received header: %.*s: %.*s\n",
		     (int) namevec.len, namevec.base, (int) valuevec.len, valuevec.base);

	struct http3_stream_context *ctx = (struct http3_stream_context *) stream_user_data;
	if (!ctx || !ctx->resp)
		return 0;

	if (ctx->resp->req->response_keepheader || ctx->resp->req->header_callback) {
		if (!ctx->resp->header)
			ctx->resp->header = wget_buffer_alloc(1024);
	}

	if (ctx->resp->header) {
		wget_buffer_printf_append(ctx->resp->header, "%.*s: %.*s\n",
					  (int) namevec.len, (char *) namevec.base, (int) valuevec.len, (char *) valuevec.base);
	}

	wget_http_parse_header_line(ctx->resp, (char *) namevec.base, (int) namevec.len,
				    (char *) valuevec.base, (int) valuevec.len);
	return 0;
}

static int deferred_consume_cb(nghttp3_conn *http3 __attribute__((unused)), 
			       int64_t stream_id, size_t consumed,
                               void *conn_user_data, 
			       void *stream_user_data __attribute__((unused)))

{
	ngtcp2_conn *conn = (ngtcp2_conn *) conn_user_data;
	int ret = _http3_consume(conn, stream_id, consumed);
	if (ret < 0) {
		error_printf("ERROR: deferred_consume_cb\n");
		return ret;
	}
	return 0;
}

static int recv_data_cb(nghttp3_conn *conn __attribute__((unused)),
                        int64_t stream_id, const uint8_t *data, 
                        size_t datalen,
                        void *conn_user_data , 
                        void *stream_user_data __attribute__((unused)))
{
	wget_http_connection *http3 = (wget_http_connection *) conn_user_data;

	debug_printf("Recieving data | %s | from stream : %ld\n", data, stream_id);

	int ret = _http3_write_data(http3->quic, stream_id, data, datalen, RESPONSE_DATA_BYTE);
	if (ret < 0) {
		error_printf("ERROR: recv_data_cb : %d\n", ret);
		return ret;
	}
    return 0;
}

static int acked_stream_data_cb(nghttp3_conn *conn __attribute__((unused)), 
				int64_t stream_id, 
				uint64_t datalen, 
				void *conn_user_data __attribute__((unused)), 
				void *stream_user_data)
{
	wget_quic *connection = (wget_quic *) stream_user_data;
	wget_quic_stream *stream = wget_quic_stream_find(connection, stream_id);

	if (stream) {
		http3_stream_mark_acked(stream, datalen);
		debug_printf("acked %zu bytes on stream #%zd\n", datalen, stream_id);
	} else {
		debug_printf("acked %zu bytes on no stream\n", datalen);	
	}

	return 0;
}

/*
* It is called when QUIC STOP_SENDING frame must be sent
* for a particular stream. Application has to tell QUIC stack
* to send this frame.
*/
static int stop_sending_cb(nghttp3_conn *conn __attribute__((unused)), 
			   int64_t stream_id, uint64_t app_error_code,
			   void *conn_user_data, void *stream_user_data __attribute__((unused)))
{
	if (_stop_sending((ngtcp2_conn *) conn_user_data, stream_id, app_error_code) < 0) {
		error_printf("ERROR: stop_sending_cb\n");
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}
	return 0;
}

/*
* It is called when QUIC RESET_STREAM frame must be sent
* for a particular stream. Application has to tell QUIC stack
* to send this frame.
*/
static int reset_stream_cb(nghttp3_conn *conn __attribute__((unused)),
			   int64_t stream_id, uint64_t app_error_code,
			   void *conn_user_data, 
			   void *stream_user_data __attribute__((unused)))
{
	if (_reset_stream((ngtcp2_conn *) conn_user_data, stream_id, app_error_code) < 0) {
		error_printf("ERROR: reset_stream_cb\n");
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}
	return 0;
}

static const nghttp3_callbacks callbacks = {
	.acked_stream_data = acked_stream_data_cb,
	.recv_data = recv_data_cb,
	.deferred_consume = deferred_consume_cb,
	.recv_header = recv_header_cb,
	.stop_sending = stop_sending_cb,
	.reset_stream = reset_stream_cb,
};

int http3_stream_push(int64_t stream_id, const void* vector,
		      void *userdata)
{
	int ret;
	wget_quic_stream *stream;
	wget_quic *quic = userdata;
	nghttp3_vec * vec = (nghttp3_vec *) vector;

	if ((stream = wget_quic_stream_find(quic, stream_id)) == NULL)
		return -1;

	if ((ret = wget_quic_stream_push(stream, (const char *) vec->base, vec->len, REQUEST_BYTE)) <= 0)
		return -1;

	return ret;
}

static void init_nv(nghttp3_nv *nv, const char *name, const char *value)
{
	nv->name = (const uint8_t *) name;
	nv->value = (const uint8_t *) value;
	nv->namelen = strlen(name);
	nv->valuelen = strlen(value);
	nv->flags = NGHTTP3_NV_FLAG_NONE;
}

static void mark_stream_as_fin(wget_quic *quic, int64_t stream_id)
{
	wget_quic_stream *stream = wget_quic_stream_find(quic, stream_id);
	if (stream)
		wget_quic_stream_set_fin(stream);
}

static int _call_data_sender(int64_t stream_id, const nghttp3_vec *vec, size_t veccnt,
			     int (*_cb_func)(int64_t, const void *, void *), void *userdata)
{
	int ret, ttl_sent = 0;

	for (unsigned i = 0; i < veccnt; i++) {
		ret = _cb_func(stream_id, (const void *)vec, userdata);
		if (ret > 0)
			ttl_sent += ret;
		else if (ret == 0)
			break;
		else
			return ret;
	}

	return ttl_sent;
}


#ifdef WITH_LIBNGHTTP3
static int http3_write_streams(wget_http_connection *http3)
{
	wget_quic_stream *streams[] = {
		http3->control_stream,
		http3->qpac_decoder_stream,
		http3->qpac_encoder_stream,
		http3->client_stream,
		NULL
	};

	return wget_quic_write_multiple(http3->quic, streams, 4);
}

/**
 * \param [in] http3 A `wget_http_connection` connection.
 * \param [in] req A `wget_http_request` structure which stores the information necessary to send request.
 * 
 * This function extracts necessary from the `wget_http_request` structure and writes the data over streams using the 
 * underlying QUIC connection after subimitting the request. This function also reads all the streams in the 
 * QUIC stack to receive the data.
 * Returns error values or WGET_E_SUCCESS.
 * 
 * \return int
*/
int wget_http3_send_request(wget_http_connection *http3, wget_http_request *req)
{
	int finish, ret;
	int64_t stream_id;
	size_t nv_len = 0;
	int n = 4 + wget_vector_size(req->headers);

	nghttp3_nv nv_headers[n], *nvp;
	nghttp3_ssize n_sent;
	nghttp3_vec *vec = wget_malloc(sizeof(nghttp3_vec)*(n-1));
	size_t veccnt = n-1;
	char resource[req->esc_resource.length + 2];

	resource[0] = '/';
	memcpy(resource + 1, req->esc_resource.data, req->esc_resource.length + 1);

	init_nv(&nv_headers[0],":method", req->method);
	init_nv(&nv_headers[1],":scheme", "https");
	init_nv(&nv_headers[2],":authority", req->esc_host.data);
	init_nv(&nv_headers[3],":path", resource);

	nv_len = n-1;
	nvp = &nv_headers[4];

	for (int it = 0; it < wget_vector_size(req->headers); it++) {
		wget_http_header_param *param = wget_vector_get(req->headers, it);
		if (!wget_strcasecmp_ascii(param->name, "Connection"))
			continue;
		if (!wget_strcasecmp_ascii(param->name, "Transfer-Encoding"))
			continue;
		if (!wget_strcasecmp_ascii(param->name, "Host")) {
			continue;
		}

		init_nv(nvp++, param->name, param->value);
	}

	struct http3_stream_context *ctx = wget_calloc(1, sizeof(struct http3_stream_context));
	ctx->resp = wget_calloc(1, sizeof(wget_http_response));
	ctx->resp->req = req;
	ctx->resp->major = 3;
	http3_ctx = ctx;

	if ((ret = nghttp3_conn_submit_request(http3->conn,
					       wget_quic_stream_get_stream_id(http3->client_stream),
					       nv_headers, nv_len, NULL, ctx)) < 0) {
		error_printf("ERROR: nghttp3_conn_submit_request: %s\n",
			nghttp3_strerror(ret));
		goto bail;
	}

	memset(vec, 0, sizeof(nghttp3_vec) * veccnt);

	do {
		n_sent = nghttp3_conn_writev_stream(http3->conn, &stream_id, &finish, vec, veccnt);

		if (n_sent > 0) {
			if ((ret = _call_data_sender(stream_id, vec, n_sent, http3_stream_push, http3->quic)) >= 0)
				nghttp3_conn_add_write_offset(http3->conn, stream_id, ret);
			else
				goto bail;
		}

		if (finish == 1) {
			mark_stream_as_fin(http3->quic, stream_id);
		}

		/* ret = wget_quic_write(http3->quic, wget_quic_stream_find(http3->quic, stream_id)); */
		/* if (ret < 0) */
		/* 	goto bail; */

	} while (finish == 0);

	ret = http3_write_streams(http3);
	if (ret < 0) {
		error_printf("Error in http3_write_streams\n");
		return -1;
	}

	wget_quic_ack(http3->quic);

	while (wget_quic_read(http3->quic) >= 0 && !wget_quic_get_is_closed(http3->quic)) {
		wget_quic_ack(http3->quic);
	}

	return WGET_E_SUCCESS;

bail:
	error_printf("ERROR: Sender callback failed: %d\n", ret);
	return WGET_E_UNKNOWN;
}
#else 
int wget_http3_send_request(wget_http_connection *http3, wget_http_request *req)
{
	return 0;
}
#endif

#ifdef WITH_LIBNGHTTP3
/**
 * \param [in] h3 A initialised `wget_http_connection` double pointer.
 * 
 * This function deletes the the nghttp3_conn and destroys the underlying 
 * `wget_quic` structure as well as the `wget_http_connection`
 * structure.
 * 
*/
void wget_http3_close(wget_http_connection **h3)
{
	wget_http_connection *http3 = *h3;
	if (http3) {
		nghttp3_conn_del(http3->conn);
		wget_quic_close(http3->quic);
		wget_quic_deinit(&http3->quic);
		xfree(http3);
	}
}
#else
void wget_http3_close(wget_http_connection **h3)
{
	return;
}
#endif


#ifdef WITH_LIBNGHTTP3
/**
 * \param [in] h3 A `wget_http_connection` double pointer.
 * \param [in] iri Internal representation of URI/IRI
 * 
 * This function initialises the `wget_http_connection` structure, creates
 * a HTTP3 client, creates a QUIC connection over socket and creates all the 
 * streams necessary over QUIC to support working of HTTP3 as per NGHTTP3 library.
 * 
 * \return int
*/
int wget_http3_open(wget_http_connection **h3, const wget_iri *iri)
{
	int ret;
	wget_http_connection *http3;
	const char *hostname;
	uint16_t port;

	hostname = iri->host;
	port = iri->port;

	http3 = *h3 = wget_calloc(1, sizeof(wget_http_connection));
	if (!http3)
		return WGET_E_MEMORY;

	http3->protocol = WGET_PROTOCOL_HTTP_3_0;

	nghttp3_settings_default(&http3->settings);

	http3->mem = nghttp3_mem_default();
	if (!http3->mem) {
		xfree(http3);
		return WGET_E_UNKNOWN;
	}

	http3->quic = wget_quic_init();
	if (!http3->quic) {
		xfree(http3);
		return WGET_E_UNKNOWN;
	}

	wget_quic_set_ssl_hostname(http3->quic, hostname);

	ret = nghttp3_conn_client_new(
		&http3->conn, &callbacks, &http3->settings, http3->mem, http3);
	if (ret < 0) {
		error_printf("Error in nghttp3_conn_client_new\n");
		wget_http3_close(&http3);
		return WGET_E_UNKNOWN;
	}

	wget_quic_set_http3_conn(http3->quic, http3->conn);

	ret = wget_quic_connect(http3->quic, hostname, port);
	if (ret < 0) {
		error_printf("Error in wget_quic_connect()\n");
		wget_http3_close(&http3);
		return WGET_E_CONNECT;
	}

	if ((http3->control_stream = wget_quic_stream_init_unidirectional(http3->quic)) == NULL) {
		return WGET_E_UNKNOWN;
	}
	if ((http3->qpac_encoder_stream = wget_quic_stream_init_unidirectional(http3->quic)) == NULL) {
		return WGET_E_UNKNOWN;
	}
	if ((http3->qpac_decoder_stream = wget_quic_stream_init_unidirectional(http3->quic)) == NULL) {
		return WGET_E_UNKNOWN;
	}
	if ((http3->client_stream = wget_quic_stream_init_bidirectional(http3->quic)) == NULL) {
		return WGET_E_UNKNOWN;
	}

	if ((ret = nghttp3_conn_bind_control_stream(http3->conn,
						    wget_quic_stream_get_stream_id(http3->control_stream))) < 0) {
		error_printf("ERROR: nghttp3_conn_bind_control_stream: %s\n",
			     nghttp3_strerror(ret));
		wget_http3_close(&http3);
		return WGET_E_UNKNOWN;
	}
	if ((ret = nghttp3_conn_bind_qpack_streams(http3->conn,
						   wget_quic_stream_get_stream_id(http3->qpac_encoder_stream),
						   wget_quic_stream_get_stream_id(http3->qpac_decoder_stream))) < 0) {
		error_printf("ERROR: nghttp3_conn_bind_qpack_streams: %s\n",
			     nghttp3_strerror(ret));
		wget_http3_close(&http3);
		return WGET_E_UNKNOWN;
	}

	return WGET_E_SUCCESS;
}
#else
int wget_http3_open(wget_http_connection **h3, const wget_iri *iri)
{
	return WGET_E_UNSUPPORTED;
}
#endif

#ifdef WITH_LIBNGHTTP3
/**
 * \param [in] http3 A 	`wget_http_connection` structure representing HTTP3 connection
 * 
 * Data incoming from server is stored in the `client_stream` using `wget_byte` struct.
 * This function iteratively dequeue's all the bytes with type data and 
 * returns it using a `wegt_http_response` structure.
 * 
 * \return wget_http_response *
*/
wget_http_response *wget_http3_get_response(wget_http_connection *http3)
{
	if (!http3_ctx)
		return NULL;

	wget_http_response *resp = http3_ctx->resp;
	if (!resp)
		return NULL;

	wget_byte *byte = (wget_byte *) wget_queue_dequeue_data_node(wget_quic_stream_get_buffer(http3->client_stream));
	char *data = NULL;
	size_t offset = 0;
	wget_http_response *resp = wget_calloc(1, sizeof(wget_http_response));
	wget_byte *byte = (wget_byte *) wget_queue_dequeue_data_node(wget_quic_stream_get_buffer(http3->client_stream));

	while (byte) {
		data = wget_realloc(data, offset + wget_byte_get_size(byte));
		memcpy(data + offset, wget_byte_get_data(byte), wget_byte_get_size(byte));
		offset += wget_byte_get_size(byte);
		byte = (wget_byte *)wget_queue_dequeue_data_node(wget_quic_stream_get_buffer(http3->client_stream));
	}

	wget_buffer *buff = wget_calloc(1, sizeof(wget_buffer));
	if (!buff) {
		xfree(resp);
		return NULL;
	}

	buff->data = data;
	buff->length = offset;
	buff->size = offset;

	resp->body = buff;
	return resp;
}
#else
wget_http_response *wget_http3_get_response(wget_http_connection *http3)
{
	return NULL;
}
#endif
