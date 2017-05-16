/*
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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
 *
 *
 * Testing Redirections
 *
 * Changelog
 * 20.10.2015  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "301 Redirect",
			.headers = {
				"Location: https://localhost:{{sslport}}/index.html",
			},
			.scope = WGET_TEST_URL_SCOPE_HTTP
		},
		{	.name = "/robots.txt",
			.code = "301 Redirect",
			.headers = {
				"Location: https://localhost:{{sslport}}/robots.txt",
			},
			.scope = WGET_TEST_URL_SCOPE_HTTP
		},
		{	.name = "/index.html",
			.code = "200 OK",
			.body = "<html><a href=\"dummy.txt\"></a><a href=\"http://localhost:{{port}}/index.html\"></a></html>",
			.headers = {
				"Content-Type: text/html",
			},
			.scope = WGET_TEST_URL_SCOPE_HTTPS
		},
		{	.name = "/robots.txt",
			.code = "301 Redirect",
			.headers = {
				"Location: https://localhost:{{sslport}}/index.html",
			},
			.scope = WGET_TEST_URL_SCOPE_HTTPS
		},
		{	.name = "/dummy.txt",
			.code = "200 OK",
			.body = "https dummy content",
			.headers = {
				"Content-Type: text/plain",
			},
			.scope = WGET_TEST_URL_SCOPE_HTTPS
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		0);

	char options[256];
	snprintf(options, sizeof(options),
		"--max-redirect=3 --recursive --span-hosts --ca-certificate=" SRCDIR "/certs/x509-ca-cert.pem https://localhost:%d/index.html",
		wget_test_get_https_server_port());

	// test-i
	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_EXECUTABLE, "wget",
		WGET_TEST_OPTIONS, options,
//		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
//		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
//			{ urls[0].name + 1, urls[1].body },
//			{	NULL } },
		0);

	exit(0);
}
