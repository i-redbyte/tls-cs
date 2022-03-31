
simple compile:

gcc -o server server.c -lssl -lcrypto

MacOs prebuild steeps:
1) brew install openssl 
2) brew install gsl
3) brew link --force openssl
4) export CFLAGS="-I/usr/local/opt/openssl@3/include"
5) export CFLAGS="-I/usr/local/opt/gsl/include"
6) export CXXFLAGS="-I/usr/local/opt/gsl/include"
7) export LIBRARY_PATH=/usr/local/Cellar/gsl/2.7.1/lib/
8) export LDFLAGS="-L/usr/local/opt/openssl@3/lib"
9) export LDFLAGS="-L/usr/local/opt/gsl/lib"
10) export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/opt/openssl/lib/

alternative:
LD_LIBRARY_PATH=/usr/local/opt/openssl@3/lib:"${LD_LIBRARY_PATH}"
CPATH=/usr/local/opt/openssl@3/include:"${CPATH}"
PKG_CONFIG_PATH=/usr/local/opt/openssl@3/lib/pkgconfig:"${PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH CPATH PKG_CONFIG_PATH

## Generate cert

openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout [KEY_NAME].pem -out [CERT_NAME].pem