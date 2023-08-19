#include <wget.h>
#include <string.h>

int main(void){
    // int ret = 0;
    // const uint16_t port = 443;
    const char *hostname = "quic.nginx.org";
    wget_iri *uri;
    wget_http_request *req;
    wget_http3_connection *http3 = NULL;

	// wget_logger_set_stream(wget_get_logger(WGET_LOGGER_DEBUG), stderr);
	// wget_logger_set_stream(wget_get_logger(WGET_LOGGER_ERROR), stderr);
	// wget_logger_set_stream(wget_get_logger(WGET_LOGGER_INFO), stdout);

    uri = wget_iri_parse(hostname, NULL);

    req = wget_http_create_request(uri, "GET");
    wget_http_add_header(req, "user-agent", "hello-client");

    http3 = wget_http3_open(uri);
    if (http3){
        if (wget_http3_send_request(http3, req) == 0){
            if (wget_http3_get_response(http3) == 0)
                return 0;
        }
    }

    return -1;
}