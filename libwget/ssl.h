#ifndef LIBWGET_SSL_H
#define LIBWGET_SSL_H

#include <wget.h>

struct config {
	const char
		*secure_protocol,
		*ca_directory,
		*ca_file,
		*cert_file,
		*key_file,
		*crl_file,
		*ocsp_server,
		*alpn;
	wget_ocsp_db
		*ocsp_cert_cache,
		*ocsp_host_cache;
	wget_tls_session_db
		*tls_session_cache;
	wget_hpkp_db
		*hpkp_cache;
	char
		ca_type,
		cert_type,
		key_type;
	bool
		check_certificate : 1,
		report_invalid_cert : 1,
		check_hostname : 1,
		print_info : 1,
		ocsp : 1,
		ocsp_date : 1,
		ocsp_stapling : 1,
		ocsp_nonce : 1,
		dane : 1;
};

extern struct config config;

#endif /* LIBWGET_SSL_H */
