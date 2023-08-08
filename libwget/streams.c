#include <config.h>

#if ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
# include <sys/ioctl.h>
#else
# include <fcntl.h>
#endif

#include <wget.h>
#include "private.h"
#include "net.h"

wget_quic_stream *stream_new(int64_t id);
wget_quic_stream *quic_stream_init(wget_quic *quic, int unidirectional);

wget_quic_stream *
stream_new(int64_t id)
{
	wget_quic_stream *stream = wget_malloc(sizeof(wget_quic_stream));
	if (!stream)
		return NULL;
	stream->id  = id;
	stream->buffer = wget_queue_init();
	stream->ack_offset = 0;
	stream->sent_offset = 0;
	return stream;
}

void 
wget_quic_set_stream(wget_quic *quic, wget_quic_stream *stream)
{
	for (int i = 0 ; i < MAX_STREAMS ; i++) {
		if (!quic->streams[i]) {
			quic->streams[i] = stream;
			quic->n_streams++;
			break;
		}
	}
}

wget_quic_stream *
wget_quic_stream_init_unidirectional(wget_quic *quic)
{
	return quic_stream_init(quic, 1);
}

wget_quic_stream *
wget_quic_stream_init_bidirectional(wget_quic *quic)
{
	return quic_stream_init(quic, 0);
}

wget_quic_stream *
quic_stream_init(wget_quic *quic, int unidirectional)
{
	int retval;
	int64_t stream_id;
	
	if (!quic)
		return NULL;
	ngtcp2_conn *conn = quic->conn;

	uint64_t (*stream_check_func)(ngtcp2_conn *);
	int (*stream_create_func)(ngtcp2_conn *, int64_t *, void *);

	stream_check_func = (unidirectional ?
			     ngtcp2_conn_get_streams_uni_left :
			     ngtcp2_conn_get_streams_bidi_left);

	if (!stream_check_func(conn)) {
		fprintf(stderr, "ERROR: Cannot open new streams!\n");
		return NULL;
	}

	stream_create_func = (unidirectional ?
			      ngtcp2_conn_open_uni_stream :
			      ngtcp2_conn_open_bidi_stream);

	if ((retval = stream_create_func(conn, &stream_id, NULL)) < 0) {
		fprintf(stderr, "ERROR: Cannot open new bidirectional stream.\n");
		return NULL;
	}

	wget_quic_stream* stream = stream_new(stream_id);
	wget_quic_set_stream(quic, stream);
	return stream;
}

/* TODO : Implement a wget_quic_stream_deinit */


int 
wget_quic_stream_push(wget_quic_stream *stream, const char *data, size_t datalen)
{
	wget_byte *buf;
	if (stream->buffer == NULL) {
		stream->buffer = wget_queue_init();
		if (!stream->buffer)
			return WGET_E_MEMORY;
		
		if ((buf = wget_byte_new(data, datalen)) == NULL)
			return WGET_E_MEMORY;
		
		if (wget_queue_enqueue(stream->buffer, buf, sizeof(buf)) == NULL)
			return WGET_E_MEMORY;
		
	} else {
		if ((buf = wget_byte_new(data, datalen)) == NULL)
			return WGET_E_MEMORY;
		
		if (wget_queue_enqueue(stream->buffer, buf, sizeof(buf)) == NULL)
			return WGET_E_MEMORY;
		
	}
	return datalen;
}

wget_quic_stream *
wget_quic_stream_find(wget_quic *quic, int64_t stream_id)
{
	int id;
  	for (int i = 0 ; i < MAX_STREAMS ; i++) {
      	wget_quic_stream *stream = quic->streams[i];
	  /*
	  	Stream_get_id is not very good name. Write getter and setter 
	  	functions for Stream as well.
	 */
		id = wget_quic_stream_get_id (stream);
		if (id >= 0 && id == stream_id)
			return stream;
    }
  	return NULL;
}

int64_t 
wget_quic_stream_get_id(wget_quic_stream *stream)
{
	if (stream)
		return stream->id;
	return -1;
}

wget_queue *
wget_quic_stream_get_buffer(wget_quic_stream *stream)
{
	if (stream)
		return stream->buffer;
	return NULL;
}

wget_quic_stream**
wget_quic_get_streams(wget_quic *quic)
{
	return quic->streams;
}