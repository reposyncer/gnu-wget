#include <config.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#ifdef WITH_OCSP
#	include <gnutls/ocsp.h>
#endif
#ifdef WITH_LIBDANE
#	include <gnutls/dane.h>
#endif
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

#include <wget.h>
#include "private.h"
#include "net.h"
#include "ssl.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

struct session_context {
	const char *
		hostname;
	wget_hpkp_stats_result
		stats_hpkp;
	uint16_t
		port;
	bool
		ocsp_stapling : 1,
		valid : 1,
		delayed_session_data : 1;
};

static gnutls_certificate_credentials_t
	credentials;
static gnutls_priority_t
	priority_cache;

#define MAX_TP_SIZE 128

static int tp_recv_func(gnutls_session_t session, const uint8_t *data, size_t data_size)
{
	int ret;
	ngtcp2_conn *conn = gnutls_session_get_ptr(session);

	ret = ngtcp2_conn_decode_and_set_remote_transport_params(conn, data, data_size);
	if (ret < 0) {
		wget_info_printf(_("ngtcp2_decode_transport_params: %s\n"), ngtcp2_strerror (ret));
		return -1;
	}

	return 0;
}

static int tp_send_func(gnutls_session_t session, gnutls_buffer_t extdata)
{
	int ret;
	uint8_t buf[MAX_TP_SIZE];
	ngtcp2_conn *conn = gnutls_session_get_ptr(session);
	const ngtcp2_transport_params *params = ngtcp2_conn_get_local_transport_params(conn);
	ngtcp2_ssize n_encoded =
		ngtcp2_transport_params_encode(buf, sizeof(buf), params);

	if (n_encoded < 0) {
		wget_debug_printf("ngtcp2_encode_transport_params: %s", ngtcp2_strerror (n_encoded));
		return -1;
	}

	ret = gnutls_buffer_append_data(extdata, buf, n_encoded);
	if (ret < 0) {
		wget_debug_printf("gnutls_buffer_append_data failed: %s", gnutls_strerror (ret));
		return -1;
	}

	return n_encoded;
}




/* Helper functions for ssl_setup_quic */
static int handshake_secret_func(gnutls_session_t session,
				 gnutls_record_encryption_level_t glevel,
				 const void *secret_read, const void *secret_write,
				 size_t secret_size)
{
	uint8_t key[64], iv[64], hp_key[64];
	ngtcp2_conn *conn = gnutls_session_get_ptr(session);
	ngtcp2_encryption_level level =
		ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(glevel);

	if (secret_read &&
		ngtcp2_crypto_derive_and_install_rx_key(conn,
							key, iv, hp_key, level,
							secret_read, secret_size) < 0)
		return -1;

	if (secret_write &&
		ngtcp2_crypto_derive_and_install_tx_key(conn,
							key, iv, hp_key, level,
							secret_write, secret_size) < 0)
		return -1;

	return 0;
}

static int handshake_read_func(gnutls_session_t session,
			       gnutls_record_encryption_level_t glevel,
			       gnutls_handshake_description_t htype,
			        const void *data, size_t data_size)
{
	int ret;

	if (htype == GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC)
		return 0;

	ngtcp2_conn *conn = gnutls_session_get_ptr (session);
	ngtcp2_encryption_level level =
		ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level (glevel);

	ret = ngtcp2_conn_submit_crypto_data (conn, level, data, data_size);
	if (ret < 0) {
		wget_debug_printf("ngtcp2_conn_submit_crypto_data: %s",
				  ngtcp2_strerror (ret));
		return -1;
	}

	return 0;
}

static int alert_read_func(gnutls_session_t session __attribute__((unused)),
			   gnutls_record_encryption_level_t level __attribute__((unused)),
			   gnutls_alert_level_t alert_level __attribute__((unused)),
			   gnutls_alert_description_t alert_desc __attribute__((unused)))
{
	return 0;
}

static int key_type(int type)
{
	if (type == WGET_SSL_X509_FMT_DER)
		return GNUTLS_X509_FMT_DER;

	return GNUTLS_X509_FMT_PEM;
}

static void set_credentials(gnutls_certificate_credentials_t creds)
{
	if (config.cert_file && !config.key_file) {
		// Use the private key from the cert file unless otherwise specified.
		config.key_file = config.cert_file;
		config.key_type = config.cert_type;
	}
	else if (!config.cert_file && config.key_file) {
		// Use the cert from the private key file unless otherwise specified.
		config.cert_file = config.key_file;
		config.cert_type = config.key_type;
	}

	if (config.cert_file && config.key_file) {
		if (config.key_type != config.cert_type) {
			// GnuTLS can't handle this
			error_printf(_("GnuTLS requires the key and the cert to be of the same type.\n"));
		}

		if (gnutls_certificate_set_x509_key_file(creds, config.cert_file, config.key_file, key_type(config.key_type)) != GNUTLS_E_SUCCESS)
			error_printf(_("No certificates or keys were found\n"));
	}

	if (config.ca_file && !wget_strcmp(config.ca_file, "system"))
		config.ca_file = wget_ssl_default_ca_bundle_path();
	if (config.ca_file) {
		if (gnutls_certificate_set_x509_trust_file(creds, config.ca_file, key_type(config.ca_type)) <= 0)
			error_printf(_("No CAs were found in '%s'\n"), config.ca_file);
	}
}

static int wget_quic_load_credentials(gnutls_certificate_credentials_t creds)
{
	int rc, ncerts = 0;

	if (config.ca_directory && *config.ca_directory && config.check_certificate) {
#if GNUTLS_VERSION_NUMBER >= 0x03000d
		if (!strcmp(config.ca_directory, "system")) {
			//Looks for places on the system where the certificates are stored.
			//Different for different systems.
			//Gets the file from paths already specified in the lib.
			//Depending on the option specified on the user.
			ncerts = gnutls_certificate_set_x509_system_trust(creds);
			if (ncerts < 0)
				debug_printf("GnuTLS system certificate store error %d\n", ncerts);
			else
				debug_printf("GnuTLS system certificate store is empty\n");
		}
#endif
		/*
			While initialising the application, we can also give a certificate
			and so this code should be same for both quic as well as tcp.
			Also if the certificate used for quic is present in the system files
			then it is great. To verify this.
		*/
		if (ncerts < 0) {
			DIR *dir;

			ncerts = 0;

			if (!strcmp(config.ca_directory, "system"))
				config.ca_directory = wget_ssl_default_cert_dir();

			if ((dir = opendir(config.ca_directory))) {
				struct dirent *dp;

				while ((dp = readdir(dir))) {
					size_t len = strlen(dp->d_name);

					if (len >= 4 && !wget_strncasecmp_ascii(dp->d_name + len - 4, ".pem", 4)) {
						char *fname = wget_aprintf("%s/%s", config.ca_directory, dp->d_name);

						if (!fname) {
							error_printf(_("Failed to allocate file name for cert '%s/%s'\n"), config.ca_directory, dp->d_name);
							continue;
						}

						struct stat st;
						if (stat(fname, &st) == 0 && S_ISREG(st.st_mode)) {
							debug_printf("GnuTLS loading %s\n", fname);
							if ((rc = gnutls_certificate_set_x509_trust_file(creds, fname, GNUTLS_X509_FMT_PEM)) <= 0)
								debug_printf("Failed to load cert '%s': (%d)\n", fname, rc);
							else
								ncerts += rc;
						}

						xfree(fname);
					}
				}

				closedir(dir);
			} else {
				error_printf(_("Failed to opendir %s\n"), config.ca_directory);
			}
		}
	}

	if (config.crl_file) {
		if ((rc = gnutls_certificate_set_x509_crl_file(creds, config.crl_file, GNUTLS_X509_FMT_PEM)) <= 0)
			error_printf(_("Failed to load CRL '%s': (%d)\n"), config.crl_file, rc);
	}

	set_credentials(creds);

	return ncerts;
}

static unsigned int wget_quic_set_alpn(gnutls_session_t session, const char *alpn)
{
	int rc;
	unsigned nprot = 0;
	const char *e, *s;

	// Choose a default value if the caller doesn't force anything
	if (!alpn)
		alpn = config.alpn;

	if (!alpn)
		return 0;

	for (nprot = 0, s = e = alpn; *e; s = e + 1)
		if ((e = strchrnul(s, ',')) != s)
			nprot++;

	if (nprot) {
		gnutls_datum_t data[16];

		for (nprot = 0, s = e = alpn; *e && nprot < countof(data); s = e + 1) {
			if ((e = strchrnul(s, ',')) != s) {
				data[nprot].data = (unsigned char *) s;
				data[nprot].size = (unsigned) (e - s);
				debug_printf("ALPN offering %.*s\n", (int) data[nprot].size, data[nprot].data);
				nprot++;
			}
		}

		if ((rc = gnutls_alpn_set_protocols(session, data, nprot, 0)))
			debug_printf("GnuTLS: Set ALPN: %s\n", gnutls_strerror(rc));
	}

	return nprot;
}


/*
	SSL open function for QUIC protocol.
	As of now OCSP is not configured.
	Also exact usage of tls_stats_data not clear.
	As of now excluded that.
*/
int wget_ssl_open_quic(wget_quic *quic)
{
	gnutls_session_t session;
	int rc, ret = WGET_E_UNKNOWN, ncerts = -1;
	const char *hostname;


	if (!quic)
		return WGET_E_INVALID;

	gnutls_global_init();

	/*
	 * This is to be decided whether to keep this or not.
	 * If this is there then a local host GNUTLS_NAME_DNS
	 * will be declared in the global quic struct.
	 */
	hostname = quic->ssl_hostname;

	/*
		As of now used same flags as used by Daiki in his repo.
		But Still to confirm are these flags available in all the
		versions of GNUTLS.
		Also to confirm how should I integrate the already available
		flag setting login in this.
	*/
	unsigned int flags = GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA;
	gnutls_init(&session, flags);

	if (hostname) {
		gnutls_server_name_set(session, GNUTLS_NAME_DNS, hostname, strlen(hostname));
		debug_printf("SNI %s\n", hostname);
	}

	gnutls_certificate_allocate_credentials(&credentials);

	ncerts = wget_quic_load_credentials(credentials);

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, credentials);
	debug_printf("Certificates loaded: %d\n", ncerts);

	const char *priorities = "NORMAL:-VERS-ALL:+VERS-TLS1.3:" \
  "-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM:" \
  "-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1:" \
  "%DISABLE_TLS13_COMPAT_MODE";
	rc = gnutls_priority_init(&priority_cache, priorities, NULL);
	if (rc != GNUTLS_E_SUCCESS)
		error_printf(_("GnuTLS: Unsupported priority string '%s': %s\n"), priorities ? priorities : "(null)", gnutls_strerror(rc));

	if ((rc = gnutls_priority_set(session, priority_cache)) != GNUTLS_E_SUCCESS)
		error_printf(_("GnuTLS: Failed to set priorities: %s\n"), gnutls_strerror(rc));

	if (config.check_certificate) {
		if (config.check_hostname) {
			gnutls_session_set_verify_cert(session, hostname, 0);
		} else {
			gnutls_session_set_verify_cert(session, NULL, 0);
		}
	}

	/*
		OCSP is not configured as of now.
		Not sure whether to confirm it or not.
	*/

	wget_quic_set_alpn(session, NULL);
	quic->ssl_session = (void *)session;

#ifdef _WIN32
	gnutls_transport_set_push_function(session, (gnutls_push_func) win32_send);
	gnutls_transport_set_pull_function(session, (gnutls_pull_func) win32_recv);
#endif

	gnutls_handshake_set_secret_function (session, handshake_secret_func);
	gnutls_handshake_set_read_function (session, handshake_read_func);
	gnutls_alert_set_read_function (session, alert_read_func);

	ret = gnutls_session_ext_register((session), "QUIC Transport Parameters",
					  NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1,
					  GNUTLS_EXT_TLS,
					  tp_recv_func, tp_send_func,
					  NULL, NULL, NULL,
					  GNUTLS_EXT_FLAG_TLS |
					  GNUTLS_EXT_FLAG_CLIENT_HELLO |
					  GNUTLS_EXT_FLAG_EE);

	return ret < 0 ? WGET_E_UNKNOWN : WGET_E_SUCCESS;
}

void wget_ssl_close_quic(wget_quic *quic)
{
	if (quic && quic->ssl_session)
		gnutls_deinit((gnutls_session_t) quic->ssl_session);
}
