#ifndef LIBWGET_HTTP3_H
#define LIBWGET_HTTP3_H

#ifdef WITH_LIBNGHTTP3
#include <nghttp3/nghttp3.h>

#endif

typedef struct wget_http3_connection_st {

    wget_quic *
        quic;
    
#ifdef WITH_LIBNGHTTP3
    nghttp3_conn *
        conn;

    const nghttp3_mem *
        mem;

    nghttp3_settings *
        settings; 
#endif

    /*
        As of now streams will be
        implemented for only Control
        Stream
    */

    wget_quic_stream *
        streams;

} wget_http3_connection_st;

#endif /* LIBWGET_HTTP3_H */