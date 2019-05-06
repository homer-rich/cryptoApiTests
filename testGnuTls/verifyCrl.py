""" Example using python-gnutls """
from __future__ import print_function
import sys, os.path
from os import walk
from ctypes import *

from gnutls.crypto import *
from gnutls.library.functions import *
from gnutls.library.types import *
from gnutls.library.constants import GNUTLS_CERT_INVALID, GNUTLS_CERT_SIGNER_NOT_FOUND,\
        GNUTLS_X509_FMT_PEM, GNUTLS_X509_FMT_DER, GNUTLS_CERT_SIGNER_NOT_CA

certs_path = os.path.realpath('../certs/')
crls_path = os.path.realpath('../crls/')

def validIndex(x):
    try:
        certLen = len(x) - 1
        retVal = int(raw_input('Input index # (Max:{}): '.format(certLen)))
        if retVal > certLen:
            raise ValueError
        return retVal
    except ValueError:
        print ('Value Error: Not a number or too large.')
        return -1

# Init vars, index < 0 for while loops
certs = []
crls = []
certIndex = -1
crlIndex = -1
crlCheck = c_uint()

# Read in certs and CRLs from os directories
for (dirpath, dirnames, filenames) in walk(certs_path):
    certs.extend(filenames)
    break
for (dirpath, dirnames, filenames) in walk(crls_path):
    crls.extend(filenames)
    break

# Specify certificate
print('\nSelect a certificate by its index')
for index, cert in enumerate(certs):
    print ('{}: {}'.format(index, cert))
while certIndex < 0:
    certIndex = validIndex(certs)

# Specify CRL
print('\nSelect a CRL by its index')
for index, crl in enumerate(crls):
    print ('{}: {}'.format(index, crl))
while crlIndex < 0:
    crlIndex = validIndex(crls)


# Load from files specified above
cert = X509Certificate(open(certs_path + '/' + certs[certIndex]).read(), \
        GNUTLS_X509_FMT_PEM if certs[certIndex].endswith('.pem') else GNUTLS_X509_FMT_DER)
crl = X509CRL(open(crls_path + '/' + crls[crlIndex]).read(), \
        GNUTLS_X509_FMT_PEM if crls[crlIndex].endswith('.pem.crl') else GNUTLS_X509_FMT_DER)

"""
  Example of a call to the GnuTLS library using byref for addresses and ._c_object for 
  the containers for crls and certs.  Any other calls to the library can be done this way.
"""

gnutls_x509_crl_verify(crl._c_object, byref(cert._c_object), 1, 0, byref(crlCheck))
crlCheck = crlCheck.value

print('\n#########################################\n')
if crlCheck & GNUTLS_CERT_INVALID:
    print('Not Trusted: ')
    if crlCheck & GNUTLS_CERT_SIGNER_NOT_FOUND:
        print('No issuer was found')
    elif crlCheck & GNUTLS_CERT_SIGNER_NOT_CA:
        print('Issuer is not a CA')
    else:
        print('Error Code: ', crlCheck)
else:
    print('Trusted\n')

