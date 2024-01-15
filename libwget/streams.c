#include <config.h>

#if ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
# include <sys/ioctl.h>
#else
# include <fcntl.h>
#endif

#include <wget.h>
#include "private.h"
#include "net.h"

wget_quic_stream *quic_stream_init(wget_quic *quic, int unidirectional);
void quic_stream_unset(wget_quic *quic, wget_quic_stream *stream);

#ifdef WITH_LIBNGTCP2
/**
 * \param [in] quic A `wget_quic` structure which represents a QUIC connection.
 * \param [in] id Integer specifying the id of the stream to be created
 * 
 * This functions intialises the `wget_quic_stream` structure.
 * It also intialises underlying  `wget_queue` and sets the stream in the 
 * array of streams present in the `wget_quic` structure.
 * 
 * \return wget_quic_stream *
*/
wget_quic_stream *
wget_quic_set_stream(int64_t id)
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
#else
wget_quic_stream *
wget_quic_set_stream(int64_t id)
{
	return NULL;
}
#endif

void
quic_stream_unset(wget_quic *quic, wget_quic_stream *stream)
{
	if (!quic || !stream)
		return;

	for (int i = 0 ; i < MAX_STREAMS ; i++){
		if (quic->streams[i] && quic->streams[i] == stream) {
			quic->streams[i] = NULL;
			quic->n_streams--;
			break;
		}
	}
	return;
}

#ifdef WITH_LIBNGTCP2
/**
 * \param [in] quic A `wget_quic` structure which represents a QUIC connection.
 * 
 * This function creates a unidirectional stream and sets the stream in the 
 * QUIC stack.
 * 
 * \return wget_quic_stream *
*/
wget_quic_stream *
wget_quic_stream_init_unidirectional(wget_quic *quic)
{
	return quic_stream_init(quic, 1);
}
#else
wget_quic_stream *
wget_quic_stream_init_unidirectional(wget_quic *quic)
{
	return NULL;
}
#endif

#ifdef WITH_LIBNGTCP2
/**
 * \param [in] quic A `wget_quic` structure which represents a QUIC connection.
 * 
 * This function creates a bidirectional stream and sets the stream in the 
 * QUIC stack.
 * 
 * \return wget_quic_stream *
*/
wget_quic_stream *
wget_quic_stream_init_bidirectional(wget_quic *quic)
{
	return quic_stream_init(quic, 0);
}
#else
wget_quic_stream_init_bidirectional(wget_quic *quic)
{
	return NULL;
}
#endif

#ifdef WITH_LIBNGTCP2
/**
 * \param [in] quic A `wget_quic` structure which represents a QUIC connection.
 * \param [in] unidirectional Integer specifies whether we need a unidirecitonal stream or not.
 * 
 * This functions opens a uni/bi directional stream as specified by \p unidirectional and sets the
 * stream in `wget_quic` structure using `wget_quic_set_stream` function.
 * 
 * \return wget_quic_stream *
*/
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

	wget_quic_stream *stream = wget_quic_set_stream(stream_id);
	if (stream) {
		for (int i = 0 ; i < MAX_STREAMS ; i++) {
			if (!quic->streams[i]) {
				quic->streams[i] = stream;
				quic->n_streams++;
				return stream;
			}
		}
	}
	return stream;
}
#else
wget_quic_stream *
quic_stream_init(wget_quic *quic, int unidirectional)
{
	return NULL;
}
#endif

#ifdef WITH_LIBNGTCP2
/**
 * \param [in] quic A `wget_quic` structure which represents a QUIC connection.
 * \param [in] s A `wget_quic_stream` structure which is to be deleted.
 * 
 * This function deinitialises the queue in the stream and deletes the queue
 * as well as stream.
*/
void
wget_quic_stream_deinit(wget_quic *quic, wget_quic_stream **s)
{
	wget_quic_stream *stream = *s;
	if (!stream)
		return;
	wget_queue_deinit(stream->buffer);
	quic_stream_unset(quic, stream);
	xfree(stream);
	return;
}
#else
void
wget_quic_stream_deinit(wget_quic *quic, wget_quic_stream **s)
{
	return;
}
#endif

/**
 * \param [in] stream A `wget_quic_stream` structure to which the data is to be pushed.
 * \param [in] data character array to be pushed into the stream.
 * \param [in] type Type of data to be pushed in.
 * 
 * This function takes \p data as parameter, pushes the data into the stream and returns 
 * the length of the data pushed or error vales.
 * 
 * \return int  
*/
int 
wget_quic_stream_push(wget_quic_stream *stream, const char *data, size_t datalen, uint8_t type)
{
	wget_byte *buf;
	if (stream->buffer == NULL) {
		stream->buffer = wget_queue_init();
		if (!stream->buffer)
			return WGET_E_MEMORY;
		
		if ((buf = wget_byte_new(data, datalen, type)) == NULL)
			return WGET_E_MEMORY;
		
		if (wget_queue_enqueue(stream->buffer, buf, wget_byte_get_struct_size()) == NULL)
			return WGET_E_MEMORY;
		
	} else {
		if ((buf = wget_byte_new(data, datalen, type)) == NULL)
			return WGET_E_MEMORY;
		
		if (wget_queue_enqueue(stream->buffer, buf, wget_byte_get_struct_size()) == NULL)
			return WGET_E_MEMORY;
		
	}
	return datalen;
}

#ifdef WITH_LIBNGTCP2
/**
 * \param [in] quic A `wget_quic` structure which represents a QUIC connection.
 * \param [in] stream_id Integer specifying the id of the stream to be searched
 * 
 * This functions searched the stream with \p stream_id as the id and returns it
 * if found or returns NULL.
 * 
 * \return wget_quic_stream *
*/
wget_quic_stream *
wget_quic_stream_find(wget_quic *quic, int64_t stream_id)
{
	int id;
  	for (int i = 0 ; i < MAX_STREAMS ; i++) {
      	wget_quic_stream *stream = quic->streams[i];
		id = wget_quic_stream_get_stream_id (stream);
		if (id >= 0 && id == stream_id)
			return stream;
    }
  	return NULL;
}
#else
wget_quic_stream *
wget_quic_stream_find(wget_quic *quic, int64_t stream_id)
{
	return NULL;
}
#endif

int64_t 
wget_quic_stream_get_stream_id(wget_quic_stream *stream)
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

size_t
wget_quic_stream_get_ack_offset(wget_quic_stream *stream)
{
	return stream->ack_offset;
}

void
wget_quic_stream_set_ack_offset(wget_quic_stream *stream, size_t offset)
{
	stream->ack_offset = offset;
}

size_t
wget_quic_stream_get_sent_offset(wget_quic_stream *stream)
{
	return stream->sent_offset;
}

void
wget_quic_stream_set_sent_offset(wget_quic_stream *stream, size_t offset)
{
	stream->sent_offset = offset;
}