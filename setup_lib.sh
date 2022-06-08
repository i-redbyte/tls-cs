#!/bin/bash
brew install openssl
brew install gsl
brew link --force openssl
export CFLAGS="-I/usr/local/opt/openssl@3/include"
export CFLAGS="-I/usr/local/opt/gsl/include"
export CXXFLAGS="-I/usr/local/opt/gsl/include"
export LIBRARY_PATH=/usr/local/Cellar/gsl/2.7.1/lib/
export LDFLAGS="-L/usr/local/opt/openssl@3/lib"
export LDFLAGS="-L/usr/local/opt/gsl/lib"
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/opt/openssl/lib/
LD_LIBRARY_PATH=/usr/local/opt/openssl@3/lib:"${LD_LIBRARY_PATH}"
CPATH=/usr/local/opt/openssl@3/include:"${CPATH}"
PKG_CONFIG_PATH=/usr/local/opt/openssl@3/lib/pkgconfig:"${PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH CPATH PKG_CONFIG_PATH

# optional steps
#echo 'export PATH="/usr/local/opt/openssl@3/bin:$PATH"' >> ~/.zshrc
#export LDFLAGS="-L/usr/local/opt/openssl@3/lib"
#export CPPFLAGS="-I/usr/local/opt/openssl@3/include"