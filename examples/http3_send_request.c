/**
 * Demonstrate sending of a HTTP3 request and printing its 
 * response.
*/

#include <wget.h>
#include <string.h>

int main(void){
    const char *hostname = "quic.nginx.org";
    char *data = NULL;
    wget_iri *uri;
    wget_http_request *req;
    wget_http_connection *http3 = NULL;

<<<<<<< HEAD
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_DEBUG), stderr);
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_ERROR), stderr);
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_INFO), stdout);
=======
wget_logger_set_stream(wget_get_logger(WGET_LOGGER_DEBUG), stderr);
wget_logger_set_stream(wget_get_logger(WGET_LOGGER_ERROR), stderr);
wget_logger_set_stream(wget_get_logger(WGET_LOGGER_INFO), stdout);
>>>>>>> 831ec624 (Remove unused wget_ssl_init_quic)

    uri = wget_iri_parse(hostname, NULL);

    req = wget_http_create_request(uri, "GET");
    uri->port = 443;
    wget_http_add_header(req, "user-agent", "hello-client");

    int ret = wget_http3_open(&http3, uri);
    if (ret >= 0){
        if (wget_http3_send_request(http3, req) == 0){
            wget_http_response *resp = wget_http3_get_response(http3);
            if (!resp){
                wget_http_free_request(&req);
                wget_http3_close(&http3);
                return -1;
            }
            fprintf(stdout, "%s", resp->body->data);
            wget_http_free_response(&resp);
            wget_http_free_request(&req);
        }else{
            wget_http_free_request(&req);
            wget_http3_close(&http3);
            return -1;
        }
    } else{
        return -1;
    }
    wget_http3_close(&http3);
    return 0;
}
