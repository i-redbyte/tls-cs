#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
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
//    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
    if (SSL_CTX_use_certificate_chain_file(ctx, CertFile) <= 0) {
//        if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_ASN1) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        abort();
    }
//    }
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


EVP_PKEY *generate_key() {
    /* Allocate memory for the EVP_PKEY structure. */
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        printf("Unable to create EVP_PKEY structure.\n");
        return NULL;
    }

    /* Generate the RSA key and assign it to pkey. */
    RSA *rsa = RSA_generate_key(4096, RSA_F4, NULL, NULL);
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        printf("Unable to generate 2048-bit RSA key.\n");
        EVP_PKEY_free(pkey);
        return NULL;
    }

    /* The key has been generated, return it. */
    return pkey;
}

/* Generates a self-signed x509 certificate. */
X509 *generate_x509(EVP_PKEY *pkey) {
    /* Allocate memory for the X509 structure. */
    X509 *x509 = X509_new();
    if (!x509) {
        printf("Unable to create X509 structure.\n");
        return NULL;
    }

    /* Set the serial number. */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    /* This certificate is valid from now until exactly one year from now. */
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    /* Set the public key for our certificate. */
    X509_set_pubkey(x509, pkey);

    /* We want to copy the subject name to the issuer name. */
    X509_NAME *name = X509_get_subject_name(x509);

    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *) "RU", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *) "RedByte", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) "localhost", -1, -1, 0);

    /* Now set the issuer name. */
    X509_set_issuer_name(x509, name);

    /* Actually sign the certificate with our key. */
    if (!X509_sign(x509, pkey, EVP_sha1())) {
        printf("Error signing certificate. \n");
        X509_free(x509);
        return NULL;
    }

    return x509;
}

int write_to_disk(EVP_PKEY *pkey, X509 *x509) {
    /* Open the PEM file for writing the key to disk. */
    FILE *pkey_file = fopen("key.pem", "wb");
    if (!pkey_file) {
        printf("Unable to open \"key.pem\" for writing.\n");
        return 0;
    }

    /* Write the key to disk. */
    int ret = PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pkey_file);

    if (!ret) {
        printf("Unable to write private key to disk.\n");
        return 0;
    }

    /* Open the PEM file for writing the certificate to disk. */
    FILE *x509_file = fopen("cert.pem", "wb");
    if (!x509_file) {
        printf("Unable to open \"cert.pem\" for writing.\n");
        return 0;
    }

    /* Write the certificate to disk. */
    ret = PEM_write_X509(x509_file, x509);
    fclose(x509_file);

    if (!ret) {
        printf("Unable to write certificate to disk.\n");
        return 0;
    }

    return 1;
}

int GenerateX509Cert() {
    EVP_PKEY *pkey = generate_key();
    if (!pkey)
        return 1;
    printf("Generating x509 certificate...\n");

    X509 *x509 = generate_x509(pkey);
    if (!x509) {
        EVP_PKEY_free(pkey);
        return 1;
    }

    printf("Writing key and certificate to disk...\n");

    int ret = write_to_disk(pkey, x509);
    EVP_PKEY_free(pkey);
    X509_free(x509);

    if (ret) {
        printf("Success!\n");
        return 0;
    } else
        return 1;
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
    SSL_library_init();
    if (access("cert.pem", F_OK) == 0) {
        printf("\ncert.pem exists\n");
    } else {
        int ret = GenerateX509Cert();
        printf("-------GenerateX509Cert-------: %d \n", ret);
    }
    portnum = Argc[1];
    printf("used port: %d \n", atoi(Argc[1]));
    ctx = InitServerCTX();
    LoadCertificates(ctx, "cert.pem", "key.pem");

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