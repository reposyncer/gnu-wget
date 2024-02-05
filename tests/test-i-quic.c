#include <config.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <wget.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

#include "quic_test_util.h"
#include "libtest.h"

void handle_child_exit (int signum) {
    (void) signum;
    wget_debug_printf("Server has been terminated!\n");
    exit(0);
}

int main(void)
{
    /* Initialise the server */
    /* Initialse the Client */
    /* Send the message and confirm its reception */

    int ret;
    wget_logger_set_stream(wget_get_logger(WGET_LOGGER_DEBUG), stdout);
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_ERROR), stdout);
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_INFO), stdout);

    /* This will kill the server process as the parent process has completed execution. */
    signal(SIGCHLD, handle_child_exit);

    const char* key_file = "/home/hmk/wget2/tests/certs/server-key.pem";
    const char* cert_file = "/home/hmk/wget2/tests/certs/server.pem";

    pid_t child_pid = start_quic_test_server(key_file, cert_file);

    sleep(5);

    const uint16_t port = 5556;
    const char *hostname = "localhost";

    wget_quic *quic = wget_quic_init();
	if (!quic) {
		fprintf(stderr, "Error in wget_quic_init()\n");
        return -1;
	}

    const char *key_path = "../certs/ca.pem";
    wget_ssl_quic_set_config_string(WGET_SSL_CA_FILE, key_path);
    wget_quic_set_ssl_hostname(quic, hostname);

    ret = wget_quic_connect(quic, hostname, port);
	if (ret < 0) {
		fprintf(stderr, "Error in wget_quic_connect()\n");
		wget_quic_deinit(&quic);
        return -1;
	}

    wget_quic_stream *stream = wget_quic_stream_init_bidirectional(quic);
    if (!stream) {
        fprintf(stderr, "ERROR: wget_quic_stream_init_bidirectional\n");
        return -1;
    }

    const char *data = "Hello World!";
    ret = wget_quic_stream_push(stream, data, strlen(data), REQUEST_BYTE);
    if (ret <= 0) {
        fprintf(stderr, "ERROR: wget_quic_stream_push\n");
        return -1;
    }

    while (1) {
	    ret = wget_quic_rw_once(quic, stream, data);
        if (ret < 0) {
            break;
        }
    }

    if (kill(child_pid, SIGTERM) == 0) {
        int status;
        waitpid(child_pid, &status, 0);
        if(WIFEXITED(status)) {
            fprintf(stdout, "Server has exited with status %d!\n", WEXITSTATUS(status));
        } else {
            fprintf(stdout, "Server has exited abnormally!\n");
        }
    } else {
        fprintf(stdout, "Error sending signal to child process!\n");
    }
    exit(EXIT_SUCCESS);
}