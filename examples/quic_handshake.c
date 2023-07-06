#include <wget.h>

int main(void){
    int ret;
    const uint16_t port = 5556;
    const char *hostname = "localhost";

    wget_quic_client *cli = wget_quic_client_init();
    if (!cli){
		fprintf(stderr, "Error in wget_quic_client_init()\n");
	}
	wget_quic *quic = wget_quic_init();
	if (!quic){
		fprintf(stderr, "Error in wget_quic_init()\n");
	}

    wget_quic_set_ssl_hostname(quic, hostname);
	wget_quic_set_remote_port(quic, port);
	wget_quic_client_set_quic(cli, quic);


    ret = wget_quic_connect(cli, hostname, port);
	if (ret < 0){
		fprintf(stderr, "Error in wget_quic_connect()\n");
	}

	ret = wget_quic_handshake(cli);
	if (ret < 0){
		fprintf(stderr, "Error in wget_quic_handshake()\n");
	}

    return 0;
}