#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <assert.h>

#define CHECK(x) assert((x)>=0)

#define CERTFILE "../certs/CA_5.pem"
#define CRLFILE "../crls/DODROOTCA5.pem.crl"

int main(void) {
    gnutls_datum_t certData;
    gnutls_datum_t crlData;
    gnutls_x509_crt_t certTest;
    gnutls_x509_crl_t crlTest;
    int ret, crlCheck;

    printf("GnuTLS Test Load from File\n");
    gnutls_load_file(CERTFILE, &certData);
    gnutls_load_file(CRLFILE, &crlData);

    gnutls_x509_crt_init(&certTest);
    gnutls_x509_crl_init(&crlTest);

    gnutls_x509_crt_import(certTest, &certData, GNUTLS_X509_FMT_PEM);
    gnutls_x509_crl_import(crlTest, &crlData, GNUTLS_X509_FMT_PEM);

    ret = gnutls_x509_crl_verify(crlTest, &certTest, 1, 0, &crlCheck);
    if (crlCheck & GNUTLS_CERT_INVALID) {
        fprintf (stderr, "Not trusted");

        if (crlCheck & GNUTLS_CERT_SIGNER_NOT_FOUND)
        fprintf (stderr, ": no issuer was found\n");
        if (crlCheck & GNUTLS_CERT_SIGNER_NOT_CA)
        fprintf (stderr, ": issuer is not a CA\n");
        if (crlCheck & GNUTLS_CERT_NOT_ACTIVATED)
        fprintf (stderr, ": not yet activated\n");
        if (crlCheck & GNUTLS_CERT_EXPIRED)
        printf (": expired\n");

        printf ("\n");
	printf ("%d",crlCheck);
    }
    else
        printf ("Trusted\n");

    gnutls_datum_t cinfo;
    printf("########## Begin Certificate Info ##########\n");
    ret = gnutls_x509_crt_print(certTest, GNUTLS_CRT_PRINT_FULL, &cinfo);
    if (ret == 0) {
        printf("\t%s\n", cinfo.data);
        gnutls_free(cinfo.data);
    }
    printf("########## End Certificate Info ##########\n");

    printf("########## Begin CRL Info ##########\n");
    ret = gnutls_x509_crl_print(crlTest, GNUTLS_CRT_PRINT_FULL, &cinfo);
    if (ret == 0) {
        printf("\t%s\n", cinfo.data);
        gnutls_free(cinfo.data);
    }
    printf("########## End CRL Info ##########\n");

    gnutls_x509_crt_deinit(certTest);
    gnutls_x509_crl_deinit(crlTest);
    gnutls_free(certData.data);
    gnutls_free(crlData.data);
    return 0;
}
