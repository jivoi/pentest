import argparse, ssl, sys, OpenSSL

desc = "Grabs SSL certificate details from a running SSL service"
parser = argparse.ArgumentParser(prog='get_ssl_cert', usage=sys.argv[0] + ' [options]', description=desc)
parser.add_argument('-i', "--hostname", type=str, help="Hostname/ip of SSL service to query", required=True)
parser.add_argument('-p', "--port", type=int, help="Port of TCP/IP SSL service", required=False, default=443)
args=parser.parse_args()

# Formatting prep
fldmap = (
	'Attribute', 's',
	'Value', 's',)

head = '\t\t\t'.join(fldmap[0:len(fldmap):2])
fmt = '\t\t\t'.join(['{' + '{0}:{1}'.format(col,fmt) + '}' \
	for col, fmt in zip( \
		fldmap[0:len(fldmap):2], \
		fldmap[1:len(fldmap):2])])

# Grab the certificate
cert = ssl.get_server_certificate((args.hostname, args.port))
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

# Convert the class
subject = x509.get_subject()
issuer = x509.get_issuer()

# Output formatted details
print("Certificate details for: " + args.hostname + '\n')
print head
print "-------------------------------------------"
print fmt.format(Attribute='Common Name:', Value=subject.commonName)
print fmt.format(Attribute='Subject Organization:', Value=subject.organizationName)
print fmt.format(Attribute='Subject Organizational Unit:', Value=subject.organizationalUnitName)
print fmt.format(Attribute='Issuer Organization:',Value=issuer.organizationName)
print fmt.format(Attribute='Issuer CN:', Value=issuer.commonName)
