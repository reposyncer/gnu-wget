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

wget_quic_stream *stream_new(int64_t id)
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
wget_quic_stream_init(wget_quic *quic)
{
	int retval;
	int64_t stream_id;
	ngtcp2_conn *conn = quic->conn;

	if(!ngtcp2_conn_get_streams_bidi_left(conn)) {
		wget_error_printf("Error: Cannot open a new stream!");
		return NULL;
	}

	if((retval = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL)) < 0) {
		wget_error_printf("Error: Cannot create a new bidirection stream");
		return NULL;
	}
	wget_quic_stream* stream = stream_new(stream_id);
	wget_quic_set_stream(quic, stream);
	return stream;
}


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
wget_quic_stream_find (wget_quic *quic, int64_t stream_id)
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