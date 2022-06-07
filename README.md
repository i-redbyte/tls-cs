### Simple compile:

```shell
gcc -o server server.c -lssl -lcrypto
```

### MacOs prebuild steeps:

- ```shell
  brew install openssl
  ```
- ```shell
  brew install gsl
  ```
- ```shell
  brew link --force openssl
  ```
- ```shell
  export CFLAGS="-I/usr/local/opt/openssl@3/include"
  ```
- ```shell
  export CFLAGS="-I/usr/local/opt/gsl/include"
  ```
- ```shell
  export CXXFLAGS="-I/usr/local/opt/gsl/include"
  ```
- ```shell
  export LIBRARY_PATH=/usr/local/Cellar/gsl/2.7.1/lib/
  ```
- ```shell
  export LDFLAGS="-L/usr/local/opt/openssl@3/lib"
  ```
- ```shell
  export LDFLAGS="-L/usr/local/opt/gsl/lib"
  ```
- ```shell
  export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/opt/openssl/lib/
  ```

### Alternative:

```shell
LD_LIBRARY_PATH=/usr/local/opt/openssl@3/lib:"${LD_LIBRARY_PATH}"
CPATH=/usr/local/opt/openssl@3/include:"${CPATH}"
PKG_CONFIG_PATH=/usr/local/opt/openssl@3/lib/pkgconfig:"${PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH CPATH PKG_CONFIG_PATH
```

## Generate cert example

```shell
openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout [KEY_NAME].pem -out [CERT_NAME].pem
```