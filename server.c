#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"

#define FAIL    -1

int OpenListener(int port) {
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        perror("can't bind port");
        abort();
    }
    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

int isRoot() {
    if (getuid() != 0) {
        return 0;
    } else {
        return 1;
    }
}

SSL_CTX *InitServerCTX(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLSv1_2_server_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile) {
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void ShowCerts(SSL *ssl) {
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    } else
        printf("No certificates.\n");
}

void Servlet(SSL *ssl) {
    char buf[1024] = {0};
    int sd, bytes;

    const char *cpValidMessage = "UserName:redbyte Password:123";
    if (SSL_accept(ssl) == FAIL)
        ERR_print_errors_fp(stderr);
    else {
        ShowCerts(ssl);
        bytes = SSL_read(ssl, buf, sizeof(buf));
        buf[bytes] = '\0';
        printf("Client msg: \"%s\"\n", buf);
        const char *ServerResponse = "Ilya Sokolov love write in C language!";
        if (bytes > 0) {
            if (strcmp(cpValidMessage, buf) == 0) {
                SSL_write(ssl, ServerResponse, strlen(ServerResponse));
            } else {
                SSL_write(ssl, "Invalid Message", strlen("Invalid Message"));
            }
        } else {
            ERR_print_errors_fp(stderr);
        }
    }
    sd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sd);
}

void GenerateX509Cert() {
    EVP_PKEY *pkey;
    pkey = EVP_PKEY_new();
    RSA *rsa;
    rsa = RSA_generate_key(
            4096,
            RSA_F4,
            NULL,
            NULL
    );
    printf("value RSA: %d\n", rsa != NULL);
    EVP_PKEY_assign_RSA(pkey, rsa);
    X509 *x509;
    x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    X509_set_pubkey(x509, pkey);
    X509_NAME *name;
    name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               (unsigned char *) "RU", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               (unsigned char *) "RedByte", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *) "localhost", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_sha1());
    FILE *key_file;
    key_file = fopen("key.pem", "wb");
    PEM_write_PrivateKey(
            key_file,
            pkey,
            EVP_des_ede3_cbc(),
            "passphrase",
            10,
            NULL,
            NULL
    );
    FILE *cert_file;
    cert_file = fopen("cert.pem", "wb");
    PEM_write_X509(
            cert_file,
            x509
    );
}

int main(int count, char *Argc[]) {
    SSL_CTX *ctx;
    int server;
    char *portnum;

    if (!isRoot()) {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if (count != 2) {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }
    GenerateX509Cert();
    SSL_library_init();
    portnum = Argc[1];
    printf("port in now: %d \n", atoi(Argc[1]));
    ctx = InitServerCTX();
    LoadCertificates(ctx, "cert.pem", "key.pem"); //TODO: move to arg

    server = OpenListener(atoi(portnum));
    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr *) &addr, &len);
        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        Servlet(ssl);
    }
    close(server);
    SSL_CTX_free(ctx);
}