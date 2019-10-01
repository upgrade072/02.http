#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/ossl_typ.h>
#include "server.h"

/* prototype from libcrypto.a */
int asn1_utctime_to_tm(struct tm *tm, const ASN1_UTCTIME *d);
int asn1_generalizedtime_to_tm(struct tm *tm, const ASN1_GENERALIZEDTIME *d);

extern server_conf SERVER_CONF;

/*
루트 인증서 생성]

CA RSA key pair 생성
openssl genrsa -out CAPriv.pem 1024

CSR 파일 생성
openssl req -new -key CAPriv.pem -out CAReq.pem
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [XX]:KO
State or Province Name (full name) []:SEOUL
Locality Name (eg, city) [Default City]:
Organization Name (eg, company) [Default Company Ltd]:ARIEL
Organizational Unit Name (eg, section) []:
Common Name (eg, your name or your server's hostname) []:NSSF
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:

X509 사용한 공개키 인증서 생성 (유효일 8 설정)
openssl x509 -req -days 8 -in CAReq.pem -signkey CAPriv.pem -out CACert.pem


==================================================================================

CACert.pem (인증서)
CAPriv.pem (키 파일)

*/

X509 *load_cert(const char *file)
{
	BIO *cert = BIO_new_file(file, "rb");
	X509 *x = NULL;

	if (cert != NULL)  {
		x = PEM_read_bio_X509_AUX(cert, NULL, (pem_password_cb *)NULL, NULL);
	}

	BIO_free(cert);
	return (x);
}

void check_expire_send_alarm(struct tm *validate_time)
{
	time_t tm_curr = {0,}, tm_expire = {0,};
	char alarm_info[1024] = {0,};
	char alarm_desc[1024] = {0,};

	char time_str[1024] = {0,};
	strftime(time_str, sizeof(time_str), "%FT%TZ", validate_time);

	tm_curr = time(NULL);
	tm_expire = mktime(validate_time);

	int remain_time = tm_expire - tm_curr;

	if (remain_time <= (10 * 24 * 60 * 60)) {
		sprintf(alarm_info, "EXPIRE-AT-%s", time_str);
		sprintf(alarm_desc, "HTTPS-CERT-EXPIRE-NOTICE");
		reportAlarm("HTTPS", SERVER_CONF.cert_event_code, SFM_ALM_CRITICAL, alarm_info, alarm_desc);

		APPLOG(APPLOG_ERR, "%s() check cert expire will come, send alarm [%d:%s:%s]",
				__func__, SERVER_CONF.cert_event_code, alarm_info, alarm_desc);
	} else {
		APPLOG(APPLOG_ERR, "%s() check cert expire still safe, expire at [%s]",
				__func__, time_str);
	}
}

void check_cert(const char *cert_file)
{
	// load CERT FILE
	X509 *x = load_cert(cert_file);
	if (x == NULL) {
		APPLOG(APPLOG_ERR, "%s() fail to load cert [%s] (x509 for PEM)", __func__, cert_file);
		goto err;
	}

	// print SUBJECT / ISSUER
	APPLOG(APPLOG_ERR, "%s() success to load cert [%s] (x509 for PEM)", __func__, cert_file);
	char *subject = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
	char *issuer = X509_NAME_oneline(X509_get_issuer_name(x), NULL, 0);
	APPLOG(APPLOG_ERR, "%s() >>>subject = %s", __func__, subject);
	APPLOG(APPLOG_ERR, "%s() >>>issuer = %s", __func__, issuer);
	OPENSSL_free(subject);
	OPENSSL_free(issuer);

	// load TIME LIMIT, CNVT TO TM STRUCT & PRINT
	const ASN1_TIME *tm = X509_get0_notAfter(x);
	struct tm validate_time = {0,};

	switch(tm->type) {
		case V_ASN1_UTCTIME:
			asn1_utctime_to_tm(&validate_time, tm);
			break;
		case V_ASN1_GENERALIZEDTIME:
			asn1_generalizedtime_to_tm(&validate_time, tm);
			break;
		default:
			APPLOG(APPLOG_ERR, "%s() invalid time format", __func__);
			goto err;
	}

	char time_str[1024] = {0,};
	strftime(time_str, sizeof(time_str), "%FT%TZ", &validate_time);
	APPLOG(APPLOG_ERR, "%s() >>>will expired at = %s", __func__, time_str);

	check_expire_send_alarm(&validate_time);
err:
	X509_free(x);
	return;
}
