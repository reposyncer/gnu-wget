#include <wget.h>
#include <string.h>

int main(void){
    int ret;
    const uint16_t port = 443;
    const char *hostname = "quic.nginx.org";

    wget_http3_connection *http3 = wget_http3_init();
    if (!http3){
        fprintf(stderr, "Error in wget_http3_init\n");
        return -1;
    }
    wget_quic_set_ssl_hostname((wget_quic *)wget_http3_get_quic_conn(http3), hostname);

    ret = wget_http3_open(http3, hostname, port);
    if (ret < 0){
        fprintf(stderr, "Error in wget_http3_open\n");
        return -1;
    }

    ret = wget_http3_init_bind_streams(http3);
    if (ret < 0){
        fprintf(stderr, "Error in wget_http3_init_bind_streams\n");
        return -1;
    }

    ret = wget_http3_send_request(http3, hostname, "/", wget_http3_stream_push);
    if (ret < 0){
        fprintf(stderr, "Error in wget_http3_send_request\n");
        return -1;
    }

    ret = wget_http3_write_all_streams(http3);
    if (ret < 0){
        fprintf(stderr, "Error in wget_http3_write_all_streams\n");
        return -1;
    }

    return 0;

}