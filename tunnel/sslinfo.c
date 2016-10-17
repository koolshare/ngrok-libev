#include "tunnel_priv.h"
#include "utils.h"
#include "list.h"
#include "khash.h"
#include "cJSON.h"
#include "common.h"


int openssl_free_info(openssl_info *sslinfo)
{
    SSL_shutdown(sslinfo->ssl);
    SSL_free(sslinfo->ssl);
    return 0;
}

//TODO use cert file https://github.com/bumptech/stud/blob/master/stud.c#L589
//http://stackoverflow.com/questions/7698488/turn-a-simple-socket-into-an-ssl-socket
//http://savetheions.com/2010/01/16/quickly-using-openssl-in-c/
int openssl_init_info(tunnel_mgr* pmgr, int server_fd, openssl_info *sslinfo)
{
    //BIO *sbio;
    sslinfo->ctx = pmgr->default_ctx;
    sslinfo->ssl = SSL_new(sslinfo->ctx);
    //sbio = BIO_new_socket(server_fd, BIO_NOCLOSE);
    //SSL_set_bio(sslinfo->ssl, sbio, sbio);
    SSL_set_fd(sslinfo->ssl, server_fd);
    return 0;
}

