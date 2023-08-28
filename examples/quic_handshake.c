/**
 * Demonstrate creating a connection with QUIC server set up at localhost.
*/

#include <wget.h>

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

    return 0;
}