/*
 * Copyright(c) 2019 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <sys/select.h>
#include <ares.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include <time.h>
#include <sys/stat.h>
#include <errno.h>

#define SERVERS    "1.0.0.1,8.8.8.8" /* DNS server to use (Cloudflare & Google) */

static int MAXWAITING; // Max. number of parallel DNS queries
static int MAXTRIES; // Max. number of tries per domain
static int TIMEOUT; // Max. number of ms for first try

static int nwaiting;

static int resolved;
static int failed;


static void write_report(const char *fname, long exec_time_)
{
	FILE *fp;
	if ((fp = fopen(fname, "a"))) {
		if (!ftell(fp)) // if file is empty
			fputs("MAXWAITING,TIMEOUT,MAXTRIES,RESOLVED,FAILED,TIME(sec)\n", fp);
		fprintf(fp, "%d,%d,%d,%d,%d,%ld\n", MAXWAITING, TIMEOUT, MAXTRIES, resolved, failed, exec_time_);
		fclose(fp);
	}
	else
		printf("Error opening file '%s': %s", fname, strerror(errno));
}

static void callback(void *arg, int status, int timeouts, struct hostent *host)
{
	nwaiting--;

	if (!host || status != ARES_SUCCESS){
		printf("Failed to lookup 1 domain: %s\n", ares_strerror(status));
		failed++;
		return;
	}

	char ip[INET_ADDRSTRLEN];
	if (host->h_addr_list[0]) {
		inet_ntop(host->h_addrtype, host->h_addr_list[0], ip, sizeof(ip));
		printf("%s: %s\n", host->h_name, ip);
		resolved++;
	}
}

static void wait_ares(ares_channel channel)
{
	struct timeval *tvp, tv;
	fd_set read_fds, write_fds;
	int nfds;

	FD_ZERO(&read_fds);
	FD_ZERO(&write_fds);
	nfds = ares_fds(channel, &read_fds, &write_fds);

	if (nfds > 0) {
		tvp = ares_timeout(channel, NULL, &tv);
		select(nfds, &read_fds, &write_fds, NULL, tvp);
		ares_process(channel, &read_fds, &write_fds);
	}
}

// ./executable MAXWAITING TIMEOUT MAXTRIES source dest
int main(int argc, char *argv[])
{
	if (argc != 6)
		return -1;

	MAXWAITING = atoi(argv[1]);
        TIMEOUT = atoi(argv[2]);
	MAXTRIES = atoi(argv[3]);

	time_t start_time = time(NULL);
	FILE * fp;
	char domain[128];
	ares_channel channel;
	int status, done = 0;
	int optmask;

	status = ares_library_init(ARES_LIB_INIT_ALL);
	if (status != ARES_SUCCESS) {
		printf("ares_library_init: %s\n", ares_strerror(status));
		return 1;
	}

	struct ares_options options = {
		.timeout = TIMEOUT,     /* set first query timeout */
		.tries = MAXTRIES       /* set max. number of tries */
	};
	optmask = ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES;

	status = ares_init_options(&channel, &options, optmask);
	if (status != ARES_SUCCESS) {
		printf("ares_init_options: %s\n", ares_strerror(status));
		return 1;
	}

	status = ares_set_servers_csv(channel, SERVERS);
	if (status != ARES_SUCCESS) {
		printf("ares_set_servers_csv: %s\n", ares_strerror(status));
		return 1;
	}

	fp = fopen(argv[4], "r");
	if (!fp)
		exit(EXIT_FAILURE);

	do {
		if (nwaiting >= MAXWAITING || done) {
			do {
				wait_ares(channel);
			} while (nwaiting > MAXWAITING);
		}

		if (!done) {
			if (fscanf(fp, "%127s", domain) == 1) {
				ares_gethostbyname(channel, domain, AF_INET, callback, NULL);
				nwaiting++;
			} else {
				fprintf(stderr, "done sending\n");
				done = 1;
			}
		}
	} while (nwaiting > 0);

	ares_destroy(channel);
	ares_library_cleanup();

	fclose(fp);

	write_report(argv[5], time(NULL)-start_time);
	return 0;
}
