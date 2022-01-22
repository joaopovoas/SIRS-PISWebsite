https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/

openssl genrsa -des3 -out myCA.key 4096

openssl req -x509 -new -nodes -key myCA.key -sha256 -days 1825 -out myCA.pem

<NEW SIGNED CERTIFICATES>

openssl genrsa -out hellfish.test.key 4096

openssl req -new -key pis.key -out pis.csr

openssl x509 -req -in pis.csr -CA myCA.pem -CAkey myCA.key -CAcreateserial -out pis.crt -days 825 -sha256 -extfile pis.ext