/*
 * Copyright (c) 2024 Free Software Foundation, Inc.
 *
 * This file is part of Wget
 *
 * Wget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 *
 * This test ensures that Wget handles a 504 Gateway Timeout response correctly.
 * Since, we do not have a direct mechanism for conditionally sending responses
 * via the HTTP Server, I've used a workaround. The server will always respond to
 * a request for File1 with a 504 Gateway Timeout. Using the --tries=2 option, we
 * ensure that Wget attempts the file only twice and then move on to the next
 * file. Finally, check the exact requests that the Server received and compare
 * them, in order, to the expected sequence of requests.
 *
 * In this case, we expect Wget to attempt File1 twice and File2 once. If Wget
 * considered 504 as a general Server Error, it would be a fatal failure and
 * Wget would request File1 only once.
*/
#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "504 Gateway Timeout",
			.body = WGET_TEST_SOME_HTML_BODY,
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/secondpage.html",
			.code = "200 Dontcare",
			.body = WGET_TEST_SOME_HTML_BODY,
			.headers = {
				"Content-Type: text/html",
			}
		}
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
        WGET_TEST_LOG_REQUESTS,
		0);

	// --accept using just suffixes
	wget_test(
		WGET_TEST_REQUEST_URLS, "index.html", "secondpage.html", NULL,
        WGET_TEST_OPTIONS, "--tries=2 --max-threads=1 --http2-request-window=1",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[1].name + 1, urls[1].body },
			{	NULL } },
		WGET_TEST_EXPECTED_REQUESTS, &(wget_test_request_t []) {
			{ "GET", "index.html" },
			{ "GET", "index.html" },
			{ "GET", "secondpage.html" },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
