### Simple compile:

```shell
gcc -o server server.c -lssl -lcrypto
```

### MacOs prebuild steeps:

If there is a need to configure ssl libs, then run the script:

```shell
sh setup_lib.sh
```

## Generate cert example

```shell
openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout [KEY_NAME].pem -out [CERT_NAME].pem
```