#!/bin/sh

fqdn=`hostname -f`
cfg=`mktemp -d --tmpdir nghq-example-XXXXXX`
trap "rm -rf '${cfg}'" 0 1 2 3 4 5 6 7 8 10 11 12 13 14

cat > "$cfg/openssl.cfg" <<EOF
[ req ]
default_days            = 30
default_bits		= 2048
default_md		= sha256
default_keyfile		= senderkey.pem
distinguished_name	= req_distinguished_name
attributes		= req_attributes
x509_extensions		= v3_ca	# The extensions to add to the self signed cert
string_mask		= utf8only
prompt			= no

[ req_distinguished_name ]
countryName			= GB
stateOrProvinceName		= Greater London
localityName			= London
organizationName		= British Broadcasting Corporation
organizationalUnitName		= Research and Development
commonName			= NGHQ Example Sender

[ req_attributes ]

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true
subjectAltName = @san

[ san ]
DNS.1 = $fqdn
EOF

/usr/sbin/ip addr | awk 'BEGIN {n=1} /^ *inet6? [0-9A-Fa-f:.]*\/.*/ {gsub(/\/.*/,"",$2); print "IP."n" = "$2; n+=1}' >> "$cfg/openssl.cfg"

openssl req -config "$cfg/openssl.cfg" -new -x509 -newkey rsa:2048 -days 30 -nodes -keyout sender.key -batch -set_serial 01 -out sender.pem
