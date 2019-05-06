/* #######################################################
Reads cert and crl from file, adds to store, then verifies
Build command:
######### gcc verifyCrl.c -lcrypto -o verifyCrl ##########
Homer April 2019
####################################################### */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

BIO *certbio = NULL;
X509_STORE *store = NULL;
const char cert_filestr[] = "../certs/CA_5.pem";
const char crl_filestr[] = "../crls/DODROOTCA5.pem.crl";
BIO *outbio = NULL;
X509 *error_cert = NULL;
X509 *cert = NULL;
X509_CRL *crl = NULL;

int addCertToStore();
int addCRLToStore();

int main () {

    X509_NAME *certsubject = NULL;
    X509_STORE_CTX *verify_ctx = NULL;
    int ret;

    // ###### OpenSSL opening calls ######
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    // ###### Initialize BIO, one for errors, one for reading in certs/crl ######
    certbio = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    // ###### Create store, exit if errors occur ######
    if (!(store = X509_STORE_new())) {
        BIO_printf(outbio, "Error creating X509_STORE_CTX object.\n");
        exit(-1);
    }
    // ###### Functions that add the cert and crl to the store
    addCertToStore();
    addCRLToStore();
    // ###### Initialize store CTX to verify against. 
    verify_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(verify_ctx, store, cert, NULL);

    ret = X509_verify_cert(verify_ctx);
    BIO_printf(outbio, "Verification return code: %d.\n", ret);

    if (ret == 0 || ret == 1)
        BIO_printf(outbio, "Verification result text: %s.\n", 
            X509_verify_cert_error_string(X509_STORE_CTX_get_error(verify_ctx)));

    if (ret == 0) {
        error_cert = X509_STORE_CTX_get_current_cert(verify_ctx);
        certsubject = X509_NAME_new();
        certsubject = X509_get_subject_name(error_cert);
        BIO_printf(outbio, "Verification failed cert: \n");
        X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
        BIO_printf(outbio, "\n");
    }

    // ###### Free up used structures ######
    X509_STORE_CTX_free(verify_ctx);
    X509_STORE_free(store);
    X509_free(cert);
    X509_CRL_free(crl);
    BIO_free_all(certbio);
    BIO_free_all(outbio);
    exit(0);
}

int addCertToStore () {
    int retVal;
    retVal = BIO_read_filename(certbio, cert_filestr);
    
    if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
        BIO_printf(outbio, "Error loading cert into memory.\n");
        retVal = -1;
        return retVal;
    }
    
    retVal = X509_STORE_add_cert(store, cert);
    return retVal;
}

int addCRLToStore () {
    int retVal;
    retVal = BIO_read_filename(certbio, crl_filestr);

    if (!(crl = PEM_read_bio_X509_CRL(certbio, NULL, 0, NULL))) {
        BIO_printf(outbio, "Error loading CRL into memory.\n");
        retVal = -1;
        return retVal;
    }

    retVal = X509_STORE_add_crl(store, crl);
    return retVal;
}

