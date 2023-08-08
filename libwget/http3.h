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
    wget_quic_stream
        * control_stream,
        * qpac_encoder_stream,
        * qpac_decoder_stream,
        * client_stream;

} wget_http3_connection_st;

#endif /* LIBWGET_HTTP3_H */