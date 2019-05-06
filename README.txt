############################################
############## CRL Tests ###################
############ Instructions ##################
############################################

Directories:
certs - location of certs for testing
crls - location of certs for testing
testGnuTls - GnuTLS test location
testOSSL - OpenSSL test location
testNSS - NSS test location

How to:
Place Certificates and CRLs in .certs and .crls directories.

GnuTLS (c):
1) In verifyCrl.c, Change the CERTFILE and CRLFILE to the files you would like to test.
2) With the GnuTLS library installed, build the c file using gcc command:
	gcc verifyCrl.c -lgnutls -o verifyCrl
3) Run the newly created exe to test the files in step 1.

GnuTLS (python):
1) With the GnuTLS Python module installed (pip install python-gnutls)
2) Run the script with the command:
	python verifyCrl.py
3) It will prompt you for a Certificate and CRL located in the certs and crls folders
up one directory from the script by default.  The directory can be edited in the python
script.

OpenSSL (c):
1) In verifyCrl.c, change the cert_filestr and crl_filestr to the files to test.
2) With the OpenSSL library installed, build the c file using the gcc command:
	gcc verifyCrl.c -lcrypto -o verifyCrl
3) Run the newly created exe to tes the files in step 1.

OpenSSL (python):
1) With the OpenSLL Python module installed (pip install pyopenssl)
2) Run the script with the command:
	python testOSSL.py
3) It will prompt you for a Certificate and CRL located in the certs and crls folders
up one directory from the script by default.  The directory can be edited in the python
script.


