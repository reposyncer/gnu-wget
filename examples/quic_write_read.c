#include <wget.h>
#include <string.h>

int main(void){
    int ret;
    const uint16_t port = 5556;
    const char *hostname = "localhost";

	wget_quic *quic = wget_quic_init();
	if (!quic){
		fprintf(stderr, "Error in wget_quic_init()\n");
        return -1;
	}

    const char *key_path = "/home/hmk/wget2/examples/credentials/ca.pem";
    wget_ssl_quic_set_config_string(WGET_SSL_CA_FILE, key_path);
    wget_quic_set_ssl_hostname(quic, hostname);


    ret = wget_quic_connect(quic, hostname, port);
	if (ret < 0){
		fprintf(stderr, "Error in wget_quic_connect()\n");
		wget_quic_deinit(&quic);
        return -1;
	}

	ret = wget_quic_handshake(quic);
	if (ret < 0){
		fprintf(stderr, "Error in wget_quic_handshake()\n");
		wget_quic_deinit(&quic);
        return -1;
	}

	wget_quic_stream *stream = wget_quic_stream_init(quic);
    if (stream){
        const char *data = "Hello World!";
        ret = wget_quic_stream_push(stream, data, strlen(data));
        ret = wget_quic_write(quic, stream);
        while(1){
            ret = wget_quic_read(quic);
            wget_byte *byte = (wget_byte *)wget_queue_dequeue(wget_quic_stream_get_buffer(stream));
            if (byte)
                fprintf(stderr ,"Data recorded : %s\n", (char *)wget_byte_get_data(byte));
            else
                break;
        }
        wget_quic_ack(quic);
    }else{
        return -1;
    }
    return 0;
}