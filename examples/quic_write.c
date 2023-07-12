#include <wget.h>

int main(void){
    int ret;
    const uint16_t port = 5556;
    const char *hostname = "localhost";

	wget_quic *quic = wget_quic_init();
	if (!quic){
		fprintf(stderr, "Error in wget_quic_init()\n");
	}

    wget_quic_set_ssl_hostname(quic, hostname);
	wget_quic_set_remote_port(quic, port);


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

	wget_quic_stream *stream = wget_quic_stream_init(quic);
	const char *data = "Hello World!";
	ret = wget_quic_stream_push(stream, data, sizeof(data));
	ret = wget_quic_write(quic, stream);
    return 0;
}