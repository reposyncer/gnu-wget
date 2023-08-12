#include <wget.h>
#include <string.h>

int main(void){
    int ret;
    const uint16_t port = 5556;
    const char *hostname = "localhost";

	wget_quic *quic = wget_quic_init();
	if (!quic){
		fprintf(stderr, "Error in wget_quic_init()\n");
	}

	const char *key_path = "/home/hmk/wget2/examples/credentials/ca.pem";
    wget_ssl_quic_set_config_string(WGET_SSL_CA_FILE, key_path);
    wget_quic_set_ssl_hostname(quic, hostname);


    ret = wget_quic_connect(quic, hostname, port);
	if (ret < 0){
		fprintf(stderr, "Error in wget_quic_connect()\n");
		wget_quic_deinit(&quic);
	}

	ret = wget_quic_handshake(quic);
	if (ret < 0){
		fprintf(stderr, "Error in wget_quic_handshake()\n");
		wget_quic_deinit(&quic);
	}

	wget_quic_stream *stream = wget_quic_stream_init_bidirectional(quic);
	if (!stream){
		return -1;
	}
	const char *data = "Hello World!";
	ret = wget_quic_stream_push(stream, data, strlen(data), REQUEST_BYTE);
	if (ret < 0){
		return ret;
	}
	ret = wget_quic_write(quic, stream);
    return ret;
}