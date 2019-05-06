import sys, os.path
from os import walk

from OpenSSL import crypto

certs_path = os.path.realpath('../certs/')
crls_path = os.path.realpath('../crls/')

def validIndex(x):
    try:
        certLen = len(x) - 1
        retVal = int(input('Input index # (Max:{}): '.format(certLen)))
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



pkey = crypto.PKey()
pkey.generate_key(crypto.TYPE_RSA, 1024)
req = crypto.X509Req()
subject = req.get_subject()
subject.O = "My Org"
subject.OU = "My OU"
req.set_pubkey(pkey)
req.sign(pkey, "md5")

cert = crypto.X509()
cert.set_serial_number(2)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(60)
cert.set_issuer(req.get_subject())
cert.set_subject(req.get_subject())
cert.set_pubkey(req.get_pubkey())
cert.sign(pkey, "md5")

certFile = open(certs_path + '/' + certs[certIndex], 'rb').read()
crlFile = open(crls_path + '/' + crls[crlIndex], 'rb').read()

cert2 = crypto.load_certificate(crypto.FILETYPE_PEM if certs[certIndex].endswith('.pem') \
        else crypto.FILETYPE_ASN1, certFile)
crl = crypto.load_crl(crypto.FILETYPE_PEM if crls[crlIndex].endswith('.pem.crl') \
        else crypto.FILETYPE_ASN1, crlFile)

#certFile.close()
#crlFile.close()

store = crypto.X509Store()
store.set_flags(crypto.X509StoreFlags.CRL_CHECK | crypto.X509StoreFlags.IGNORE_CRITICAL)
store.add_cert(cert2)
store.add_crl(crl)

storeContext = crypto.X509StoreContext(store, cert2)

try:
    storeContext.verify_certificate()
except:
    err = sys.exc_info()
    print ('Not Valid; \nError: {}', err)

# Pretty print of certificate
#print (crypto.dump_certificate(crypto.FILETYPE_TEXT, cert2).decode('utf-8'))
#print (crypto.dump_crl(crypto.FILETYPE_TEXT, crl).decode('utf-8'))
