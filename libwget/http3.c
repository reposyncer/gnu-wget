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
#include "http3.h"

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


void
http3_stream_mark_acked (wget_quic_stream *stream, size_t datalen)
{
  	while (stream) {
		wget_byte *head  = (wget_byte *)wget_queue_peek_transmitted_node(stream->buffer);
		if (wget_byte_get_size (head) > datalen)
			break;

		stream->ack_offset += wget_byte_get_size (head);
		datalen -= wget_byte_get_size (head);
		wget_queue_dequeue_transmitted_node(stream->buffer);
		return;
    }
}

static int _stop_sending(ngtcp2_conn *conn,
			 int64_t stream_id, uint64_t app_error_code)
{
	/* Close read side of a stream abruptly */
	int ret = ngtcp2_conn_shutdown_stream_read(conn, 0,
						      stream_id, app_error_code);
	if (ret < 0) {
		fprintf(stderr, "ERROR: ngtcp2_conn_shutdown_stream_read: %s\n",
			ngtcp2_strerror(ret));
		return -1;
	}

	return 0;
}

/* Questionable */
static int _reset_stream(ngtcp2_conn *conn,
			 int64_t stream_id, uint64_t app_error_code)
{
	/* Close write side of a stream abruptly */
	int ret = ngtcp2_conn_shutdown_stream_write(conn, 0,
						       stream_id, app_error_code);
	if (ret < 0) {
		fprintf(stderr, "ERROR: ngtcp2_conn_shutdown_stream_write: %s\n",
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
	if (!quic){
		return -1;
	}
	wget_quic_stream *stream = wget_quic_stream_find(quic, stream_id);
	if(stream){
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
	fprintf(stderr, "recv_header_cb Here!\n");
	nghttp3_vec namevec, valuevec;
	namevec = nghttp3_rcbuf_get_buf(name);
	valuevec = nghttp3_rcbuf_get_buf(value);
	fprintf(stderr, "Received header: %.*s: %.*s\n",
		(int)namevec.len, namevec.base, (int)valuevec.len, valuevec.base);

	return 0;
}

static int deferred_consume_cb(nghttp3_conn *http3 __attribute__((unused)), 
                            int64_t stream_id, size_t consumed,
                            void *conn_user_data, 
                            void *stream_user_data __attribute__((unused)))

{
	fprintf(stderr, "deferred_consume_cb Here!\n");
    ngtcp2_conn *conn = (ngtcp2_conn *)conn_user_data;
    int ret = _http3_consume(conn, stream_id, consumed);
	if (ret < 0)
		fprintf(stderr, "ERROR: deferred_consume_cb\n");
    return ret;
}

static int stream_close_cb(nghttp3_conn *conn, int64_t stream_id,
                        uint64_t app_error_code, 
                        void* conn_user_data __attribute__((unused)), 
                        void* stream_user_data __attribute__((unused)))
{
	fprintf(stderr, "stream_close_cb Here!\n");
    int ret = nghttp3_conn_close_stream(conn, stream_id, app_error_code);
	// if (ret < 0)
	// 	return ret;
	// wget_http3_connection *http3 = (wget_http3_connection *)conn_user_data;
	// wget_quic_stream_unset(http3->quic, stream_id);
	// int ret = ngtcp2_conn_shutdown_stream(http3->quic->conn, 0, stream_id, app_error_code);
	if (ret < 0)
		fprintf(stderr, "ERROR: stream_close_cb\n");
    return ret;
}

static int recv_data_cb(nghttp3_conn *conn __attribute__((unused)),
                        int64_t stream_id, const uint8_t *data, 
                        size_t datalen,
                        void *conn_user_data , 
                        void *stream_user_data __attribute__((unused)))
{
	fprintf(stderr, "recv_data_cb Here!\n");
    fprintf(stderr, "Recieving data | %s | from stream : %ld\n", data, stream_id);
	wget_http3_connection *http3 = (wget_http3_connection *)conn_user_data;
	int ret = _http3_write_data(http3->quic, stream_id, data, datalen, RESPONSE_DATA_BYTE);
	if (ret < 0){
		fprintf(stderr, "ERROR: recv_data_cb : %d\n", ret);
	}
    return ret;
}

static int acked_stream_data_cb(nghttp3_conn *conn __attribute__((unused)), 
						int64_t stream_id, 
                        uint64_t datalen, 
						void *conn_user_data __attribute__((unused)), 
                        void *stream_user_data)
{
	fprintf(stderr, "acked_stream_data_cb Here!\n");
	wget_quic *connection = (wget_quic *)stream_user_data;
	wget_quic_stream *stream = wget_quic_stream_find(connection, stream_id);

	if (stream) {
		http3_stream_mark_acked (stream, datalen);
		fprintf(stderr, "acked %zu bytes on stream #%zd\n", datalen, stream_id);
	} else 
		fprintf(stderr, "acked %zu bytes on no stream\n", datalen);	
    return 0;
}

static int stop_sending_cb(nghttp3_conn *conn __attribute__((unused)), 
				 int64_t stream_id, uint64_t app_error_code,
			     void *conn_user_data, void *stream_user_data __attribute__((unused)))
{
	/*
	 * It is called when QUIC STOP_SENDING frame must be sent
	 * for a particular stream. Application has to tell QUIC stack
	 * to send this frame.
	 */
	fprintf(stderr, "stop_sending_cb Here!\n");
	if (_stop_sending((ngtcp2_conn *)conn_user_data, stream_id, app_error_code) < 0){
		fprintf(stderr, "ERROR: stop_sending_cb\n");
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}
	return 0;
}

static int reset_stream_cb(nghttp3_conn *conn __attribute__((unused)),
			     int64_t stream_id, uint64_t app_error_code,
			     void *conn_user_data, 
				 void *stream_user_data __attribute__((unused)))
{
	/*
	 * It is called when QUIC RESET_STREAM frame must be sent
	 * for a particular stream. Application has to tell QUIC stack
	 * to send this frame.
	 */
	fprintf(stderr, "reset_stream_cb Here!\n");

	if (_reset_stream((ngtcp2_conn *)conn_user_data, stream_id, app_error_code) < 0){
		fprintf(stderr, "ERROR: reset_stream_cb\n");
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}
	return 0;
}

static const nghttp3_callbacks callbacks = {
    .acked_stream_data = acked_stream_data_cb,
    .stream_close = stream_close_cb,
    .recv_data = recv_data_cb,
    .deferred_consume = deferred_consume_cb,
    .recv_header = recv_header_cb,
    .stop_sending = stop_sending_cb,
    .reset_stream = reset_stream_cb,
};

int wget_http3_stream_push(int64_t stream_id, const void* vector, 
							void *userdata)
{
	int ret;
	wget_quic_stream *stream;
	wget_quic *quic = userdata;
	nghttp3_vec * vec = (nghttp3_vec *)vector;


	if ((stream = wget_quic_stream_find(quic, stream_id)) == NULL)
		return -1;

	if ((ret = wget_quic_stream_push(stream, (const char *)vec->base, vec->len, REQUEST_BYTE)) <= 0)
		return -1;

	return ret;
}

/* 
    The streams to be added should be present in the 
    QUIC structure before calling this function and should
    be initialised.
*/
int wget_http3_init_bind_streams(wget_http3_connection *http3)
{
	int ret;

	http3->control_stream = wget_quic_stream_init_unidirectional(http3->quic);
	http3->qpac_encoder_stream = wget_quic_stream_init_unidirectional(http3->quic);
	http3->qpac_decoder_stream = wget_quic_stream_init_unidirectional(http3->quic);
	http3->client_stream = wget_quic_stream_init_bidirectional(http3->quic);

	if ((ret = nghttp3_conn_bind_control_stream(http3->conn, wget_quic_stream_get_id(http3->control_stream))) < 0) {
		fprintf(stderr, "ERROR: nghttp3_conn_bind_control_stream: %s\n",
			nghttp3_strerror(ret));
		return -1;
	}
	if ((ret = nghttp3_conn_bind_qpack_streams(http3->conn,
						      wget_quic_stream_get_id(http3->qpac_encoder_stream), wget_quic_stream_get_id(http3->qpac_decoder_stream))) < 0) {
		fprintf(stderr, "ERROR: nghttp3_conn_bind_qpack_streams: %s\n",
			nghttp3_strerror(ret));
		return -1;
	}

	return 0;
}

static void init_nv(nghttp3_nv *nv, const char *name, const char *value)
{
	nv->name = (const uint8_t *) name;
	nv->value = (const uint8_t *) value;
	nv->namelen = strlen(name);
	nv->valuelen = strlen(value);
	/* TODO Check with different implementation of the flags */
	nv->flags = NGHTTP3_NV_FLAG_NONE;
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

/*
    sender_func : should find the stream with given stream ID
                and then push the data into the stream.
*/

int wget_http3_send_request(wget_http3_connection *http3, wget_http_request *req)
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


	if ((ret = nghttp3_conn_submit_request(http3->conn,
						  wget_quic_stream_get_id(http3->client_stream),
						  nv_headers, nv_len, NULL, NULL)) < 0) {
		fprintf(stderr, "ERROR: nghttp3_conn_submit_request: %s\n",
			nghttp3_strerror(ret));
		return -1;
	}

	memset(vec, 0, sizeof(nghttp3_vec) * veccnt);

	/* Gather outgoing data until nghttp3 tells us there is no more (finish = 1) */
	do {
		n_sent = nghttp3_conn_writev_stream(http3->conn, &stream_id, &finish, vec, veccnt);
		if (n_sent > 0) {
			if ((ret = _call_data_sender(stream_id, vec, n_sent, wget_http3_stream_push, http3->quic)) >= 0)
				nghttp3_conn_add_write_offset(http3->conn, stream_id, ret);
			else
				goto bail;
		}
	} while (finish == 0);

	ret = wget_http3_write_streams(http3);
	if (ret < 0){
		fprintf(stderr, "Error in wget_http3_write_streams\n");
		return -1;
	}

	ret = wget_http3_read_streams(http3);
	if (ret < 0){
		fprintf(stderr, "Error in wget_http3_read_streams\n");
		return -1;
	}

	return 0;

bail:
	fprintf(stderr, "ERROR: Sender callback failed: %d\n", ret);
	return -1;
}

/*
    wget_http3_init : It will initilise all the elements inside the http3 struct
    wget_http3_open : It will initilise a HTTP/3 client and supporting QUIC connection.
*/

wget_http3_connection *wget_http3_init(void) 
{
    wget_http3_connection *http3 = wget_malloc(sizeof(wget_http3_connection));
    if (!http3)
        return NULL;

    http3->settings = wget_malloc(sizeof(nghttp3_settings));
    if (!http3->settings){
		xfree(http3);
        return NULL;
	}

    nghttp3_settings_default(http3->settings);

    http3->mem = nghttp3_mem_default();
    if (!http3->mem){
		xfree(http3);
        return NULL;
	}

    http3->quic = wget_quic_init();
    if (!http3->quic){
		xfree(http3);
        return NULL;
	}

    http3->control_stream = NULL;
	http3->qpac_encoder_stream = NULL;
	http3->qpac_decoder_stream = NULL;
	http3->client_stream = NULL;

    return http3;
}

void wget_http3_deinit(wget_http3_connection *http3)
{
    if (http3) {
        xfree(http3->settings);
        wget_quic_deinit(&http3->quic);
        xfree(http3);
    }
}


/*
	Handle all the deinit functions here.
*/
wget_http3_connection * wget_http3_open(const wget_iri *iri)
{
    int ret;
	wget_http3_connection *http3 = NULL;
	const char
		*hostname;
	uint16_t
		port;

	hostname = iri->host;
	port = 443;

	http3 = wget_http3_init();
    if (!http3){
        fprintf(stderr, "Error in wget_http3_init\n");
        return NULL;
    }

	wget_quic_set_ssl_hostname((wget_quic *)wget_http3_get_quic_conn(http3), hostname);

	ret = nghttp3_conn_client_new(
			&http3->conn, &callbacks, http3->settings, http3->mem, http3);
	if (ret < 0) {
        fprintf(stderr, "Error in nghttp3_conn_client_new\n");
        wget_http3_deinit(http3);
		return NULL;
	}

	wget_quic_set_http3_conn(http3->quic, http3->conn);

    ret = wget_quic_connect(http3->quic, hostname, port);
	if (ret < 0) {
		fprintf(stderr, "Error in wget_quic_connect()\n");
		wget_http3_deinit(http3);
        return NULL;
	}

	ret = wget_quic_handshake(http3->quic);
	if (ret < 0) {
		fprintf(stderr, "Error in wget_quic_handshake()\n");
		wget_http3_deinit(http3);
        return NULL;
	}

	ret = wget_http3_init_bind_streams(http3);
    if (ret < 0){
        fprintf(stderr, "Error in wget_http3_init_bind_streams\n");
        return NULL;
    }

	return http3;
}

int wget_http3_write_streams(wget_http3_connection *http3)
{
	int ret;
	ret = wget_quic_write(http3->quic, http3->control_stream);
	if (ret < 0)
		return ret;

	ret = wget_quic_write(http3->quic, http3->qpac_encoder_stream);
	if (ret < 0)
		return ret;
	
	ret = wget_quic_write(http3->quic, http3->qpac_decoder_stream);
	if (ret < 0)
		return ret;

	ret = wget_quic_write(http3->quic, http3->client_stream);
	if (ret < 0)
		return ret;

	wget_quic_ack(http3->quic);

	return 0;

}

int wget_http3_get_response(wget_http3_connection *http3)
{
	wget_byte *byte = (wget_byte *)wget_queue_dequeue_data_node(wget_quic_stream_get_buffer(http3->client_stream));
	while (byte){
		char *data = wget_malloc(wget_byte_get_size(byte));
		memcpy(data, wget_byte_get_data(byte), wget_byte_get_size(byte));
		fprintf(stderr ,"%s", data);
		byte = (wget_byte *)wget_queue_dequeue_data_node(wget_quic_stream_get_buffer(http3->client_stream));
		xfree(data);
	}

	return 0;
}

int wget_http3_read_streams(wget_http3_connection *http3)
{
	int ret = 0;
	while(wget_quic_read(http3->quic) >= 0 && !wget_quic_get_is_closed(http3->quic)){
		continue;
	}
	return ret;
}

void *wget_http3_get_quic_conn(wget_http3_connection *http3)
{
	if (http3){
		return (void *)http3->quic;
	}
	return NULL;
}