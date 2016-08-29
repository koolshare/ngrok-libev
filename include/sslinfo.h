#ifndef __SSLINFO_H__
#define __SSLINFO_H__
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/asn1.h>

struct _tunnel_mgr;
typedef struct _openssl_info
{
    SSL *ssl;
    SSL_CTX *ctx;

} openssl_info;

int openssl_free_info(openssl_info *sslinfo);
int openssl_init_info(struct _tunnel_mgr* pmgr, int server_fd, openssl_info *sslinfo);
#endif

