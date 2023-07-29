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

#ifdef WITH_LIBNGHTTP3
#include <nghttp3/nghttp3.h>

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
    if (!http3->settings)
        return NULL;

    nghttp3_settings_default(http3->settings);

    http3->mem = nghttp3_mem_default();
    if (!http3->mem)
        return NULL;

    http3->quic = wget_quic_init();
    if (!http3->quic)
        return NULL;

    return http3;
}