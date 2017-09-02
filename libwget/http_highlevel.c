/*
 * Copyright(c) 2013 Tim Ruehsen
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
 * Highlevel HTTP functions
 *
 * Changelog
 * 21.01.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <wget.h>
#include "private.h"
#include "http.h"

struct wget_highlevel_config
{
	wget_iri_t *uri;
	wget_vector_t *headers;
	wget_vector_t *challenges;
	wget_http_connection_t *conn;

	wget_http_header_callback_t header_callback;
	void *header_user_data;

	/*
	 * Accepted values for 'output_to'.
	 * Zero (0) is implicit and means no output.
	 */
#define FILENAME 1 
#define STREAM   2
#define FUNCTION 3
#define FD       4
	int output_to;
	union {
		const char *saveas_name;
		FILE *saveas_stream;
		int saveas_fd;
		struct {
			void *cb;
			void *userdata;
		} saveas_callback;
	} output;
	FILE *saveas_stream;
	wget_http_body_callback_t saveas_callback;
	void *saveas_user_data;

	const void *body;
	size_t bodylen;

	const char
		*scheme,
		*url,
		*url_encoding,
		*saveas_name;

	int
		saveas_fd,
		keep_header,
		keep_alive,
		max_redirections;
};

static wget_http_connection_t *_get_connection(wget_http_t *req)
{
	wget_iri_t *uri = req->uri;
	wget_http_connection_t *conn = req->conn;

	// open/reopen/reuse HTTP/HTTPS connection
	if (conn && !wget_strcmp(conn->esc_host, uri->host) &&
		conn->scheme == uri->scheme &&
		conn->port == uri->port)
	{
		debug_printf("reuse connection %s\n", conn->esc_host);
	} else {
		if (conn) {
			debug_printf("close connection %s\n", conn->esc_host);
			wget_http_close(&conn);
		}
		if (wget_http_open(&conn, uri) == WGET_E_SUCCESS)
			debug_printf("opened connection %s\n", conn->esc_host);
	}

	return conn;
}

static wget_http_response_t *_send_request(wget_http_t *req, wget_http_connection_t *conn))
{
	wget_http_response_t *resp = NULL;
	int rc = wget_http_send_request(conn, req);

	if (rc == 0) {
		// set the callback for the response HTTP headers
		if (req->header_callback.cb) {
			wget_http_request_set_header_cb(req->request,
				req->header_callback.cb,
				req->header_callback.userdata);
		}

		wget_http_request_set_int(req, WGET_HTTP_RESPONSE_KEEPHEADER, 1);

		switch (req->output_to) {
		case FILENAME:
		{
			FILE *fp = fopen(req->output.saveas_name, "wb");

			if (!fp) {
				debug_printf("Failed to open '%s' for writing",
					req->output.saveas_name);
				goto end;
			}

			wget_http_request_set_body_cb(req->request,
				_stream_callback,
				fp);
		}
			break;
		case STREAM:
			wget_http_request_set_body_cb(req->request,
				_stream_callback,
				req->output.saveas_stream);
			break;
		case FUNCTION:
			wget_http_request_set_body_cb(req->request,
				req->output.saveas_callback.cb,
				req->output.saveas_callback.body_user_data);
			break;
		case FD:
			wget_http_request_set_body_cb(req->request,
				_fd_callback,
				&req->output.saveas_fd);
			break;
		default:
			if (req->output_to != 0)
				error_printf("Invalid value %d for 'output_to'\n", req->output_to);
			break;
		}

		resp = wget_http_get_response(conn);
	}

end:
	return resp;
}

static void _follow_redirect(wget_http_t *req, int free_uri)
{
	char uri_sbuf[1024];
	wget_buffer_t uri_buf;

	// if relative location, convert to absolute
	wget_buffer_init(&uri_buf, uri_sbuf, sizeof(uri_sbuf));
	wget_iri_relative_to_abs(req->uri,
		resp->location, strlen(resp->location),
		&uri_buf);

	if (free_uri)
		wget_iri_free(&req->uri);

	req->uri = wget_iri_parse(uri_buf.data, NULL);
	wget_buffer_deinit(&uri_buf);
}

static int _stream_callback(wget_http_response_t *resp G_GNUC_WGET_UNUSED, void *user_data, const char *data, size_t length)
{
	FILE *stream = (FILE *) user_data;

	size_t nbytes = fwrite(data, 1, length, stream);

	if (nbytes != length) {
		error_printf(_("Failed to write %zu bytes of data (%d)\n"), length, errno);

		if (feof(stream))
			return -1;
	}

	return 0;
}
static int _fd_callback(wget_http_response_t *resp G_GNUC_WGET_UNUSED, void *user_data, const char *data, size_t length)
{
	int fd = *(int *) user_data;
	ssize_t nbytes = write(fd, data, length);

	if (nbytes == -1 || (size_t) nbytes != length)
		error_printf(_("Failed to write %zu bytes of data (%d)\n"), length, errno);

	return 0;
}

static struct wget_highlevel_config *_init_config()
{
	struct wget_highlevel_config *conf = xnew(struct wget_highlevel_config);

	// TODO complete

	conf->keep_alive = 0;
	conf->headers = wget_vector_create(8, 8, NULL);
	conf->challenges = NULL;

	return conf;
}

static void _deinit_config(wget_http_t **reqp)
{
	wget_http_t *req;

	if (reqp && *reqp) {
		req = *reqp;

		if (req->uri)
			wget_iri_free(&req->uri);
		if (req->challenges)
			wget_vector_deinit(&req->challenges);

		xfree(*reqp);
		*reqp = NULL;
	}
}

static wget_http_response_t *_wget_http_get(wget_http_t *req, wget_iri_t *uri)
{
	wget_cookie_db_t *cookie_db;
	wget_http_response_t *resp = NULL;
	int cookies_enabled = !!wget_global_get_int(WGET_COOKIES_ENABLED);
	int redirection_level = 0;

	if (!req->uri) {
		if (!req->url) {
			error_printf(_("No target URL or URI was provided\n"));
			goto out;
		}

		req->uri = wget_iri_parse(req->url, req->url_encoding);
		if (!req->uri) {
			error_printf(_("Error parsing URL\n"));
			goto out;
		}
	}

	/*
	 * TODO cookies???
	 *
	 *  - allow user to enable/disable cookies and to provide their own cookie DB
	 *  - what does wget_global_get_ptr() do?
	 */
	if (cookies_enabled)
		cookie_db = (wget_cookie_db_t *) wget_global_get_ptr(WGET_COOKIE_DB);

	while (req->uri && redirection_level <= req->max_redirections) {
		// create a HTTP/1.1 GET request.
		// the only default header is 'Host: domain' (taken from uri)
		req->request = wget_http_create_request(req->uri, scheme);

		// add HTTP headers
		for (it = 0; it < wget_vector_size(headers); it++)
			wget_http_add_header_param(req->request, wget_vector_get(headers, it));

		if (req->challenges) {
			// There might be more than one challenge, we could select the most secure one.
			// TODO fix this - For simplicity and testing we just take the first for now.
			// the following adds an Authorization: HTTP header
			wget_http_add_credentials(req->request,
				wget_vector_get(req->challenges, 0),
				http_username, http_password, 0);
			wget_http_free_challenges(&req->challenges);
		}

		// use keep-alive if you want to send more requests on the same connection
		// http_add_header(req, "Connection", "keep-alive");
		if (req->keep_alive)
			wget_http_add_header(req->request, "Connection", "keep-alive");

		// enrich the HTTP request with the uri-related cookies we have
		if (cookie_db) {
			const char *cookie_string;
			if ((cookie_string = wget_cookie_create_request_header(cookie_db, req->uri))) {
				wget_http_add_header(req->request, "Cookie", cookie_string);
				xfree(cookie_string);
			}
		}

		// TODO review this (maybe there's no need for 'keep_alive' param?)
		if (connp) {
			wget_http_add_header(req->request, "Connection", "keepalive");
		}

		conn = _get_connection(req);

		if (conn) {
			if (req->body && req->bodylen) {
				wget_http_request_set_body(req->request,
					NULL,
					wget_memdup(body, bodylen),
					bodylen);
			}

			resp = _send_request(req, conn);
		}

		wget_http_free_request(&req);

		if (!resp)
			goto out;

		// server doesn't support or want keep-alive
		if (!resp->keep_alive)
			wget_http_close(&conn);

		if (cookie_db) {
			// check and normalization of received cookies
			wget_cookie_normalize_cookies(req->uri, resp->cookies);

			// put cookies into cookie-store (also known as cookie-jar)
			wget_cookie_store_cookies(cookie_db, resp->cookies);
		}

		if (resp->code == 401 && !req->challenges) { // Unauthorized
			if ((req->challenges = resp->challenges)) {
				resp->challenges = NULL;
				wget_http_free_response(&resp);
				if (redirection_level == 0 && req->max_redirections) {
					redirection_level = req->max_redirections; // just try one more time with authentication
					continue; // try again with credentials
				}
			}
			break;
		}

		// 304 Not Modified
		if (resp->code / 100 == 2 || resp->code / 100 >= 4 || resp->code == 304)
			break; // final response

		if (resp->location) {
			_follow_redirect(req, bits.free_uri);
			bits.free_uri = 1;

			redirection_level++;
			continue;
		}

		break;
	}


out:
	if (connp) {
		*connp = conn;
	} else {
		wget_http_close(&conn);
	}

	wget_http_free_challenges(&challenges);

//	wget_vector_clear_nofree(headers);
	wget_vector_free(&headers);

	if (bits.free_uri)
		wget_iri_free(&uri);

	return resp;
}

/*
 * High-level API configuration setters
 */
void wget_http_set_url(wget_http_t *req, const char *url)
{
	if (req) {
		if (req->uri)
			wget_iri_free(&req->uri);
		req->url = url;
	}
}

void wget_http_set_url_encoding(wget_http_t *req, const char *enc)
{
	if (req) {
		if (req->uri)
			wget_iri_free(&req->uri);
		if (enc && *enc)
			req->url_encoding = enc;
		else
			req->url_encoding = "utf-8";
	}
}

void wget_http_set_uri(wget_http_t *req, const wget_iri_t *uri)
{
	if (req) {
		if (req->uri)
			wget_iri_free(&req->uri);
		req->uri = wget_iri_clone(uri);
	}
}

void wget_http_set_credentials(wget_http_t *req, const char *username, const char *password)
{
	// TODO implement (should populate the 'challenges' field)
}

void wget_http_header(wget_http_t *req, const char *name, const char *val)
{
	wget_http_header_t header = {
		.name = name,
		.value = val
	};
	wget_vector_add(req->headers, &header, sizeof(header));
}

void wget_http_keep_alive(wget_http_t *req, int keep_alive)
{
	if (req && (keep_alive == 0 || keep_alive == 1))
		req->keep_alive = keep_alive;
}

void wget_http_keep_response_headers(wget_http_t *req, int keep)
{
	if (req && (keep == 0 || keep == 1))
		req->keep_header = keep;
}

void wget_http_set_header_callback(wget_http_r *req, wget_http_header_callback_t cb, void *userdata)
{
	if (req) {
		req->header_callback.cb = cb;
		req->header_callback.userdata = userdata;
	}
}

void wget_http_set_connection_ptr(wget_http_t *req, wget_http_connection_t *conn)
{
	if (req)
		req->conn = conn;
}

void wget_http_set_max_redirections(wget_http_t *req, int max_redirections)
{
	if (req && max_redirections >= 0)
		req->max_redirections = max_redirections;
}

void wget_http_set_output_filename(wget_http_t *req, const char *fname)
{
	if (req) {
		if (fname && *fname) {
			req->output_to = FILENAME;
			req->output.saveas_name = fname;
		} else {
			req->output_to = 0;
		}
	}
}

void wget_http_set_output_stream(wget_http_t *req, FILE *stream)
{
	if (req) {
		if (stream) {
			req->output_to = STREAM;
			req->output.saveas_stream = stream;
		} else {
			req->output_to = 0;
		}
	}
}

void wget_http_set_output_callback(wget_http_t *req, void *func, void *userdata)
{
	if (req) {
		if (func) {
			req->output_to = FUNCTION;
			req->output.saveas_callback.cb = func;
			req->output.saveas_callback.userdata = userdata;
		} else {
			req->output_to = 0;
		}
}

void wget_http_set_output_fd(wget_http_t *req, int fd)
{
	if (req) {
		if (fd > 0) {
			req->output_to = FD;
			req->output.saveas_fd = fd;
		} else {
			req->output_to = 0;
		}
	}
}

/*
 * High-level HTTP API
 */
wget_http_t *wget_http_new(const char *url, const char *encoding, const char *method)
{
	// TODO implement
}

void wget_http_destroy(wget_http_t **req)
{
	// TODO implement
}

wget_http_response_t *wget_http_send(wget_http_request_t *req)
{
	// TODO implement
}

wget_http_response_t *wget_http_get(int first_key, ...)
{
	wget_vector_t *headers = wget_vector_create(8, 8, NULL);
	wget_iri_t *uri = NULL;
	wget_http_connection_t *conn = NULL, **connp = NULL;
	wget_http_request_t *req;
	wget_http_response_t *resp = NULL;
	wget_vector_t *challenges = NULL;
	wget_cookie_db_t *cookie_db = NULL;
	FILE *saveas_stream = NULL;
	wget_http_body_callback_t saveas_callback = NULL;
	int saveas_fd = -1;
	wget_http_header_callback_t header_callback = NULL;
	va_list args;
	const char *url = NULL,	*url_encoding = NULL, *scheme = "GET";
	const char *http_username = NULL, *http_password = NULL;
	const char *saveas_name = NULL;
	int key, it, max_redirections = 5, redirection_level = 0;
	size_t bodylen = 0;
	const void *body = NULL;
	void *header_user_data = NULL, *body_user_data = NULL;

	/* TODO _wget_http_new() to be static */
	wget_http_t *req = _wget_http_new();

	struct {
		unsigned int
			cookies_enabled : 1,
			keep_header : 1,
			free_uri : 1;
	} bits = {
		.cookies_enabled = !!wget_global_get_int(WGET_COOKIES_ENABLED)
	};

	va_start(args, first_key);
	for (key = first_key; key; key = va_arg(args, int)) {
		switch (key) {
		case WGET_HTTP_URL:
			url = va_arg(args, const char *);
			break;
		case WGET_HTTP_URI:
			uri = va_arg(args, wget_iri_t *);
			break;
		case WGET_HTTP_URL_ENCODING:
			url_encoding = va_arg(args, const char *);
			break;
		case WGET_HTTP_HEADER_ADD:
			wget_http_header(req,
				va_arg(args, const char *), // header name
				va_arg(args, const char *)); // header value
			break;
		case WGET_HTTP_CONNECTION_PTR:
			connp = va_arg(args, wget_http_connection_t **);
			break;
		case WGET_HTTP_RESPONSE_KEEPHEADER:
			bits.keep_header = va_arg(args, int);
			break;
		case WGET_HTTP_MAX_REDIRECTIONS:
			max_redirections = va_arg(args, int);
			break;
		case WGET_HTTP_BODY_SAVEAS:
			saveas_name = va_arg(args, const char *);
			break;
		case WGET_HTTP_BODY_SAVEAS_STREAM:
			saveas_stream = va_arg(args, FILE *);
			break;
		case WGET_HTTP_BODY_SAVEAS_FUNC:
			saveas_callback = va_arg(args, wget_http_body_callback_t);
			body_user_data = va_arg(args, void *);
			break;
		case WGET_HTTP_BODY_SAVEAS_FD:
			saveas_fd = va_arg(args, int);
			break;
		case WGET_HTTP_HEADER_FUNC:
			header_callback = va_arg(args, wget_http_header_callback_t);
			header_user_data = va_arg(args, void *);
			break;
		case WGET_HTTP_SCHEME:
			scheme = va_arg(args, const char *);
			break;
		case WGET_HTTP_BODY:
			body = va_arg(args, const void *);
			bodylen = va_arg(args, size_t);
			break;
		default:
			error_printf(_("Unknown option %d\n"), key);
			goto out;
		}
	}
	va_end(args);

	if (connp)
		wget_http_set_connection_ptr(req, *connp);
}
